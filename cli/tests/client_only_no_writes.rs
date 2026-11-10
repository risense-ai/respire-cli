//! Client-only errors must not create a profile merely to initialize file logging.
#[cfg(unix)]
#[test]
fn client_only_status_preserves_fresh_and_legacy_homes() -> anyhow::Result<()> {
    use std::{fs, process::Command};
    for legacy in [false, true] {
        for env_only in [false, true] {
            let fixture = tempfile::tempdir()?;
            let home = fixture.path().join("home");
            fs::create_dir(&home)?;
            let marker = home.join(".onememory/client.json");
            let original = b"{\"addr\":\"https://fixture.invalid\"}\n";
            if legacy {
                fs::create_dir(home.join(".onememory"))?;
                fs::write(&marker, original)?;
            }
            let mut command = Command::new(env!("CARGO_BIN_EXE_rsrs"));
            command.env_clear()
                .env("HOME", &home)
                .env("USERPROFILE", &home)
                .env("XDG_CONFIG_HOME", fixture.path().join("config"))
                .env("XDG_DATA_HOME", fixture.path().join("data"))
                .env("XDG_CACHE_HOME", fixture.path().join("cache"))
                .env("XDG_RUNTIME_DIR", fixture.path().join("runtime"))
                .env("RSRS_RPC_PORT", "1")
                .env("RSRS_UPDATE_CHECK", "0")
                .env("RSRS_NO_AUTOSYNC", "1")
                .env("RSRS_LANG", "en")
                .current_dir(fixture.path());
            if env_only {
                command.env("RSRS_CLIENT_ONLY", "1");
            } else {
                command.arg("--client-only");
            }
            let output = command.args(["--json", "status"]).output()?;
            assert!(!output.status.success(), "missing host must not be accepted");
            let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(envelope["status"], "fail");
            // Directory assertions catch empty log/profile creation too, not just files.
            assert_eq!(fs::read_dir(fixture.path())?.count(), 1);
            assert_eq!(fs::read_dir(&home)?.count(), usize::from(legacy));
            assert!(!home.join(".rsrs").exists());
            if legacy {
                assert_eq!(fs::read(&marker)?, original);
                assert_eq!(fs::read_dir(home.join(".onememory"))?.count(), 1);
            }
        }
    }
    Ok(())
}
