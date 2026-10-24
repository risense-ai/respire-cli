//! Explicit synthetic benchmark; never reads an account, library or transcript.
use anyhow::{Context, Result};
use respire_core_sdk::Core;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Instant};

fn verified(path: &Path, expected: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).with_context(|| format!("read fixture {}", path.display()))?;
    anyhow::ensure!(
        hex::encode(Sha256::digest(&bytes)) == expected,
        "fixture checksum mismatch"
    );
    Ok(bytes)
}
fn threads() -> Option<usize> {
    std::fs::read_dir("/proc/self/task")
        .ok()
        .map(|entries| entries.count())
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let root = Path::new(args.get(1).context("provide verified model directory")?);
    let legacy = args.iter().any(|arg| arg == "--legacy");
    let (name, hash) = if legacy {
        (
            "model_quantized.onnx",
            "0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d",
        )
    } else {
        (
            "model_quantized.cpu-v1.ort",
            "7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff",
        )
    };
    let model = verified(&root.join("onnx").join(name), hash)?;
    let tokenizer = verified(
        &root.join("tokenizer.json"),
        "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790",
    )?;
    let content = "Synthetic indexing fixture: the lunar research station stores calibration decisions and validates retrieval results. ".repeat(70);
    let mut reports = Vec::new();
    let mut baseline_threads = None;
    for background in [1usize, 4] {
        let mut core = Core::new()?;
        anyhow::ensure!(
            core.capabilities()?["inference_thread_contract"] == 1,
            "SDK lacks thread isolation contract"
        );
        let config = json!({"model":"m3","asset_id":hash,"engine":"cpu","execution_timeout_secs":120,
            "session_options_id":format!("synthetic-thread-probe-{background}"),"background_intra_threads":background,
            "cpu_owned_ort_experiment":!legacy});
        if legacy {
            core.load_model(config.clone(), &model, &tokenizer)?;
        } else {
            let mut upload = core.begin_model_input(model.len())?;
            for chunk in model.chunks(1 << 20) {
                upload.append(chunk)?;
            }
            upload.commit(config.clone(), &tokenizer)?;
        }
        let status = core.call("engine_control", json!({"action":"inference_status"}))?;
        anyhow::ensure!(
            status["intra_threads"] == json!({"foreground":1,"background":background}),
            "loaded native policy mismatch"
        );
        let mut wrong = config.clone();
        wrong["reuse_current"] = json!(true);
        wrong["background_intra_threads"] = json!(if background == 1 { 4 } else { 1 });
        anyhow::ensure!(
            core.load_model(wrong, &[], &[]).is_err(),
            "cached model reused across thread policies"
        );
        let warm = core.call("prepare", json!({"model":"m3","content":content}))?;
        anyhow::ensure!(
            warm["artifact"]
                .as_str()
                .is_some_and(|artifact| !artifact.is_empty()),
            "background warmup failed"
        );
        let native_threads = threads();
        if background == 1 {
            baseline_threads = native_threads;
        }
        if let (Some(baseline), Some(actual)) = (baseline_threads, native_threads) {
            anyhow::ensure!(
                actual >= baseline + background - 1,
                "native ORT thread pool did not reflect background configuration"
            );
        }
        let (index_seconds, foreground_seconds) = std::thread::scope(|scope| -> Result<_> {
            let mut reuse = config.clone();
            reuse["reuse_current"] = json!(true);
            let foreground = scope.spawn(move || -> Result<Vec<f64>> {
                let mut handle = Core::new()?;
                handle.load_model(reuse, &[], &[])?;
                let mut times = Vec::new();
                for _ in 0..3 {
                    let started = Instant::now();
                    let result = handle.call(
                        "model_probe",
                        json!({"model":"m3","text":"synthetic foreground query"}),
                    )?;
                    anyhow::ensure!(
                        result["ready"] == true && result["dimensions"] == 1024,
                        "foreground inference failed"
                    );
                    times.push(started.elapsed().as_secs_f64());
                }
                Ok(times)
            });
            let mut index = Vec::new();
            for _ in 0..3 {
                let started = Instant::now();
                let prepared = core.call("prepare", json!({"model":"m3","content":content}))?;
                anyhow::ensure!(
                    prepared["artifact"]
                        .as_str()
                        .is_some_and(|artifact| !artifact.is_empty()),
                    "index inference failed"
                );
                index.push(started.elapsed().as_secs_f64());
            }
            Ok((
                index,
                foreground
                    .join()
                    .map_err(|_| anyhow::anyhow!("foreground probe panicked"))??,
            ))
        })?;
        reports.push(json!({"mode":if legacy { "legacy-onnx" } else { "streamed-owned-ort" },
            "foreground_threads":1,"background_threads":background,"native_process_threads":native_threads,
            "background_prepare_seconds":index_seconds,"concurrent_foreground_probe_seconds":foreground_seconds,
            "cache_policy_mismatch_rejected":true}));
        core.call("engine_control", json!({"action":"reset"}))?;
    }
    println!("{}", serde_json::to_string_pretty(&Value::Array(reports))?);
    Ok(())
}
