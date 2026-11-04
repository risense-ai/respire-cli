//! Acceptance checks for the current/former recall channels and `rsrs due`.
//!
//! Every check runs against a fresh isolated library: a changed fact is kept as
//! a superseding record (the old wording stays quotable), the current channel
//! scores only live records, the former channel walks back through the chain,
//! expired statements leave the current view without being deleted, and open
//! promises surface in `rsrs due` until a replacement fulfils them.

use super::with_isolated_session;
use crate::{capture_run, output::ResultEnvelope};
use anyhow::{Context, Result};
use serde_json::json;

fn command(args: &[&str], exit: i32) -> Result<ResultEnvelope> {
    let result = capture_run(
        std::iter::once("--json".to_owned())
            .chain(args.iter().map(|arg| (*arg).to_owned()))
            .collect(),
    );
    anyhow::ensure!(
        result.exit == exit,
        "{args:?}: expected {exit}, got {}: {:?}",
        result.exit,
        result.envelope
    );
    Ok(result.envelope)
}

struct DirectGuard {
    direct: bool,
    defer: bool,
    user: Option<std::ffi::OsString>,
}
impl DirectGuard {
    fn enter() -> Self {
        let user = std::env::var_os("RSRS_USER");
        std::env::set_var("RSRS_USER", "test");
        Self {
            direct: crate::DIRECT_MODE.swap(true, std::sync::atomic::Ordering::Relaxed),
            defer: crate::DEFER_PROFILE_OUTPUT.replace(true),
            user,
        }
    }
}
impl Drop for DirectGuard {
    fn drop(&mut self) {
        crate::DIRECT_MODE.store(self.direct, std::sync::atomic::Ordering::Relaxed);
        crate::DEFER_PROFILE_OUTPUT.set(self.defer);
        match &self.user {
            Some(value) => std::env::set_var("RSRS_USER", value),
            None => std::env::remove_var("RSRS_USER"),
        }
    }
}

/// Recall heat is written by the recall statistics path: queued for the write
/// worker, persisted inline when no worker runs. Tests drop the worker flag so
/// `recall_count` moves synchronously and the "no bump" assertion is real.
struct WorkerGuard(bool);
impl WorkerGuard {
    fn inline_stats() -> Self {
        let previous = crate::rpc::worker_active();
        crate::rpc::set_worker_active(false);
        Self(previous)
    }
}
impl Drop for WorkerGuard {
    fn drop(&mut self) {
        crate::rpc::set_worker_active(self.0);
    }
}

fn recall_args(args: &[&str]) -> Result<ResultEnvelope> {
    let _worker = WorkerGuard::inline_stats();
    let mut input = vec!["recall"];
    input.extend(args);
    command(&input, 0)
}

fn recall(query: &str) -> Result<ResultEnvelope> {
    recall_args(&[query, "--titles", "--limit", "10"])
}

fn show(id: &str) -> Result<ResultEnvelope> {
    command(&["show", id], 0)
}

/// Ids of a `--titles` recall, in ranked order.
fn ids(result: &ResultEnvelope) -> Vec<String> {
    result
        .details
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn detail<'a>(result: &'a ResultEnvelope, id: &str) -> Option<&'a serde_json::Value> {
    result
        .details
        .as_array()?
        .iter()
        .find(|row| row["id"].as_str() == Some(id))
}

fn item_value<'a>(result: &'a ResultEnvelope, title: &str) -> Option<&'a str> {
    // Rows read "<score> <title> [label]": match the title in position so a
    // label that mentions another title ("[supersedes alcohol-before]") does
    // not satisfy a lookup for that title.
    result.items.iter().map(|item| item.value.as_str()).find(|value| {
        let Some((_, rest)) = value.split_once(' ') else {
            return false;
        };
        rest == title || rest.starts_with(&format!("{title} [")) || rest.starts_with(&format!("{title} "))
    })
}

/// Metadata writes (`--valid-until`, `--review-at`) need contract 1, which needs
/// the local metadata gate. `metadata enable` takes the library lock itself
/// (worker off, then released on exit), and the gate's writes check the flag,
/// not a held lock — so nothing stays held here: a held lock would deadlock the
/// recalls below, which re-acquire it whenever their worker flag is off.
fn enable_metadata() -> Result<()> {
    let _store = crate::build_local()?;
    let _worker = WorkerGuard::inline_stats();
    command(&["metadata", "enable"], 0)?;
    Ok(())
}

/// Seed the shared fixture: `before` states the old fact, `after` supersedes it.
/// The replacement body carries the "previously" cue so the auto-channel query
/// clears the cosine gate against it — the test-mode hashing embedder scores
/// exact token overlap, unlike a dense production model. The old record is
/// reached through the chain walk, which never re-scores.
fn seed_replacement(before: &str, after: &str) -> Result<(String, String)> {
    let old = command(
        &[
            "remember",
            before,
            "--title",
            "alcohol-before",
            "--importance",
            "important",
            "--force",
        ],
        0,
    )?;
    let old_id = old.summary["id"].as_str().context("old id")?.to_owned();
    let new = command(
        &[
            "remember",
            after,
            "--title",
            "alcohol-now",
            "--importance",
            "important",
            "--force",
            "--supersedes",
            &old_id,
        ],
        0,
    )?;
    let new_id = new.summary["id"].as_str().context("new id")?.to_owned();
    Ok((old_id, new_id))
}

#[test]
fn current_channel_returns_only_the_replacement_and_keeps_history_readable() -> Result<()> {
    with_isolated_session(|_| {
        let _direct = DirectGuard::enter();
        let old = command(
            &[
                "remember",
                "alcoholstance: never drink alcohol, zero tolerance",
                "--title",
                "alcohol-before",
                "--importance",
                "important",
                "--force",
            ],
            0,
        )?;
        let old_id = old.summary["id"].as_str().context("old id")?.to_owned();

        // Baseline: the live record answers the query on its own, and the hit
        // moves its heat once - that is the number the filter must not touch.
        let baseline = recall("alcoholstance")?;
        assert!(
            ids(&baseline).contains(&old_id),
            "baseline must find the live record: {baseline:?}"
        );
        let before = show(&old_id)?.details["recall_count"].clone();

        let new = command(
            &[
                "remember",
                "alcoholstance: drink a little alcohol now and then",
                "--title",
                "alcohol-now",
                "--importance",
                "important",
                "--force",
                "--supersedes",
                &old_id,
            ],
            0,
        )?;
        let new_id = new.summary["id"].as_str().context("new id")?.to_owned();

        let current = recall("alcoholstance")?;
        let current_ids = ids(&current);
        assert!(
            current_ids.contains(&new_id),
            "the replacement must answer the current question: {current:?}"
        );
        assert!(
            !current_ids.contains(&old_id),
            "the superseded record must leave the current channel: {current:?}"
        );

        // The old wording stays quotable, and the current recall did not move its heat.
        let shown = show(&old_id)?;
        assert_eq!(
            shown.details["entry"]["content"].as_str().context("old content")?,
            "alcoholstance: never drink alcohol, zero tolerance"
        );
        assert_eq!(
            shown.details["recall_count"],
            before,
            "a current-channel recall must not bump the superseded record"
        );
        Ok(())
    })
}

#[test]
fn former_channel_walks_back_from_the_live_hit_to_the_replacement() -> Result<()> {
    with_isolated_session(|_| {
        let _direct = DirectGuard::enter();
        let (old_id, new_id) = seed_replacement(
            "alcoholstance: never drink alcohol, zero tolerance",
            "alcoholstance: now drink a little alcohol, previously zero tolerance",
        )?;

        // Auto channel: a past-seeking cue in the query opens the history walk.
        let auto = recall("previously alcoholstance")?;
        let auto_ids = ids(&auto);
        assert!(
            auto_ids.contains(&new_id),
            "the live replacement still answers: {auto:?}"
        );
        assert!(
            auto_ids.contains(&old_id),
            "the former channel must surface the superseded record: {auto:?}"
        );
        let label = item_value(&auto, "alcohol-before")
            .context("former channel must list the old record")?;
        assert!(
            label.contains("[superseded by"),
            "the old record must point at its replacement: {label}"
        );
        assert_eq!(
            detail(&auto, &old_id).map(|row| row["superseded_by"].clone()),
            Some(json!(new_id)),
            "JSON details must carry the replacement id"
        );

        // Explicit channel selection with a neutral query.
        let flagged = recall_args(&["alcoholstance", "--titles", "--when", "former"])?;
        assert!(
            ids(&flagged).contains(&old_id),
            "--when former must walk the chain too: {flagged:?}"
        );
        assert!(
            item_value(&flagged, "alcohol-before")
                .is_some_and(|value| value.contains("[superseded by")),
            "flagged former recall must label the old record: {flagged:?}"
        );
        Ok(())
    })
}

#[test]
fn expired_record_leaves_the_current_channel_but_stays_open_by_id() -> Result<()> {
    with_isolated_session(|_| {
        let _direct = DirectGuard::enter();
        enable_metadata()?;

        let live = command(
            &[
                "remember",
                "residenceaddress: 9 Pine Avenue, quiet street",
                "--title",
                "address-now",
                "--importance",
                "important",
                "--force",
            ],
            0,
        )?;
        let live_id = live.summary["id"].as_str().context("live id")?.to_owned();
        let expiring = command(
            &[
                "remember",
                "residenceaddress: 42 Maple Street, old flat",
                "--title",
                "address-before",
                "--importance",
                "important",
                "--force",
                "--valid-until",
                "2099-01-01T00:00:00.000Z",
            ],
            0,
        )?;
        let expiring_id = expiring
            .summary["id"]
            .as_str()
            .context("expiring id")?
            .to_owned();

        // While the window is open both addresses answer.
        let before = recall("residenceaddress")?;
        assert!(
            ids(&before).contains(&expiring_id),
            "a valid address must answer before expiry: {before:?}"
        );

        // Close the window: the statement stops being current, but is not deleted.
        command(
            &[
                "update",
                &expiring_id,
                "--valid-until",
                "2000-01-01T00:00:00.000Z",
            ],
            0,
        )?;
        let after = recall("residenceaddress")?;
        let after_ids = ids(&after);
        assert!(
            after_ids.contains(&live_id),
            "the live address must keep answering: {after:?}"
        );
        assert!(
            !after_ids.contains(&expiring_id),
            "an expired statement must leave the current channel: {after:?}"
        );

        // The record itself survives: an explicit id still opens it.
        let shown = show(&expiring_id)?;
        assert_eq!(
            shown.details["entry"]["content"]
                .as_str()
                .context("expired content")?,
            "residenceaddress: 42 Maple Street, old flat"
        );
        Ok(())
    })
}

fn due_ids(result: &ResultEnvelope) -> Vec<String> {
    result
        .details
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn due_lists_open_promise_tasks_until_a_replacement_fulfills_them() -> Result<()> {
    with_isolated_session(|_| {
        let _direct = DirectGuard::enter();
        enable_metadata()?;

        // An open promise whose review time has passed.
        let promise = command(
            &[
                "remember",
                "promise: send the quarterly report to the team",
                "--title",
                "quarterly-report",
                "--type",
                "task",
                "--importance",
                "important",
                "--force",
                "--review-at",
                "2020-01-01T00:00:00.000Z",
            ],
            0,
        )?;
        let promise_id = promise.summary["id"].as_str().context("promise id")?.to_owned();

        // A promise that is not due yet.
        let future = command(
            &[
                "remember",
                "promise: renew the domain name next year",
                "--title",
                "domain-renewal",
                "--type",
                "task",
                "--importance",
                "important",
                "--force",
                "--review-at",
                "2099-01-01T00:00:00.000Z",
            ],
            0,
        )?;
        let future_id = future.summary["id"].as_str().context("future id")?.to_owned();

        // A past review date is not a promise unless it is an important task.
        let note = command(
            &[
                "remember",
                "standing note that carries a review date",
                "--title",
                "not-a-promise",
                "--importance",
                "important",
                "--force",
                "--review-at",
                "2020-01-01T00:00:00.000Z",
            ],
            0,
        )?;
        let note_id = note.summary["id"].as_str().context("note id")?.to_owned();
        let diary = command(
            &[
                "remember",
                "diary task that carries a review date",
                "--title",
                "diary-promise",
                "--type",
                "task",
                "--importance",
                "trivial",
                "--force",
                "--review-at",
                "2020-01-01T00:00:00.000Z",
            ],
            0,
        )?;
        let diary_id = diary.summary["id"].as_str().context("diary id")?.to_owned();

        let due = command(&["due"], 0)?;
        let listed = due_ids(&due);
        assert!(
            listed.contains(&promise_id),
            "the due promise must be listed: {due:?}"
        );
        assert!(
            !listed.contains(&future_id),
            "a future promise is not due: {due:?}"
        );
        assert!(
            !listed.contains(&note_id),
            "only tasks count as promises: {due:?}"
        );
        assert!(
            !listed.contains(&diary_id),
            "diary importance never qualifies as a promise: {due:?}"
        );

        // Fulfillment is a superseding record, not a forget.
        command(
            &[
                "remember",
                "promise fulfilled: quarterly report sent to the team",
                "--title",
                "quarterly-report-sent",
                "--type",
                "task",
                "--importance",
                "important",
                "--force",
                "--supersedes",
                &promise_id,
            ],
            0,
        )?;
        let after = command(&["due"], 0)?;
        assert!(
            !due_ids(&after).contains(&promise_id),
            "a superseded promise must leave the due list: {after:?}"
        );
        Ok(())
    })
}
