//! Embedded CLI version. Printed by `--version`, `-v`, and `rsrs v`.

use crate::output::{Item as OutputItem, ResultEnvelope, Status};

pub fn embedded() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn line() -> String {
    format!("rsrs {}", embedded())
}

pub fn emit(json: bool) -> anyhow::Result<()> {
    if json {
        let mut envelope = ResultEnvelope::new(
            "version",
            Status::Ok,
            serde_json::json!({"version": embedded()}),
            vec![OutputItem::new(
                "version",
                Status::Ok,
                embedded().to_owned(),
            )],
        );
        envelope.details = serde_json::json!({"bin": embedded()});
        println!("{}", envelope.render(true)?);
    } else {
        println!("{}", line());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn embedded_is_nonempty_semverish() -> Result<(), String> {
        let v = super::embedded();
        if v.is_empty() {
            return Err("empty version".into());
        }
        if !v.chars().next().unwrap_or('x').is_ascii_digit() {
            return Err(format!("version should start with a digit: {v}"));
        }
        if !super::line().starts_with("rsrs ") {
            return Err(super::line());
        }
        Ok(())
    }
}
