//! Defaults and validation for the host recall-settings form.
use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

pub const MODES: &[&str] = &["legacy", "attention", "attention_anchor", "auto"];
pub const NUMERIC: &[(&str, f64)] = &[
    ("fusion_alpha", 0.20),
    ("fusion_beta", 0.25),
    ("fusion_temperature", 1.0),
    ("fusion_gate_recency", 0.02),
    ("fusion_gate_recency_temporal", 1.0),
    ("fusion_gate_hot", 0.10),
    ("fusion_gate_tree", 0.02),
    ("fusion_temporal_alpha", 0.15),
];

pub fn defaults() -> Map<String, Value> {
    let mut values = Map::new();
    values.insert("fusion".into(), json!("legacy"));
    for &(key, value) in NUMERIC {
        values.insert(key.into(), json!(value));
    }
    values
}

pub fn validate(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .context("recall_fusion must be an object")?;
    for (key, value) in object {
        if key == "fusion" {
            anyhow::ensure!(
                value.as_str().is_some_and(|mode| MODES.contains(&mode)),
                "fusion must be legacy, attention, attention_anchor or auto"
            );
        } else {
            anyhow::ensure!(
                NUMERIC.iter().any(|(name, _)| *name == key),
                "unknown recall_fusion setting {key}"
            );
            let number = value
                .as_f64()
                .with_context(|| format!("{key} must be a number"))?;
            let valid = if key == "fusion_temperature" {
                number > 0.0 && number <= 10.0
            } else {
                (0.0..=1.0).contains(&number)
            };
            anyhow::ensure!(
                number.is_finite() && valid && (key != "fusion_temperature" || number as f32 > 0.0),
                "invalid recall_fusion setting {key}"
            );
        }
    }
    let alpha = object
        .get("fusion_alpha")
        .and_then(Value::as_f64)
        .unwrap_or(0.20) as f32;
    let beta = object
        .get("fusion_beta")
        .and_then(Value::as_f64)
        .unwrap_or(0.25) as f32;
    anyhow::ensure!(
        alpha + beta <= 1.0,
        "fusion_alpha + fusion_beta must not exceed 1"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_modes_match_the_form_contract() -> Result<()> {
        let expected = json!({
            "fusion":"legacy", "fusion_alpha":0.20, "fusion_beta":0.25,
            "fusion_temperature":1.0, "fusion_gate_recency":0.02,
            "fusion_gate_recency_temporal":1.0, "fusion_gate_hot":0.10,
            "fusion_gate_tree":0.02, "fusion_temporal_alpha":0.15
        });
        assert_eq!(Value::Object(defaults()), expected);
        validate(&expected)?;
        assert_eq!(MODES, ["legacy", "attention", "attention_anchor", "auto"]);
        for mode in MODES {
            validate(&json!({"fusion":mode}))?;
        }
        validate(&json!({}))?;
        Ok(())
    }

    #[test]
    fn numeric_ranges_include_limits_but_reject_invalid_combinations() -> Result<()> {
        for &(key, _) in NUMERIC {
            if key == "fusion_temperature" {
                continue;
            }
            for number in [0.0, 1.0] {
                let mut value = json!({"fusion_alpha":0.0,"fusion_beta":0.0});
                value[key] = json!(number);
                validate(&value)?;
            }
            for number in [-0.01, 1.01] {
                assert_eq!(
                    validate(&json!({(key):number}))
                        .err()
                        .map(|error| error.to_string()),
                    Some(format!("invalid recall_fusion setting {key}"))
                );
            }
        }
        for value in [
            json!({"fusion_alpha":0.5,"fusion_beta":0.5}),
            json!({"fusion_alpha":0.75}),
        ] {
            validate(&value)?;
        }
        for value in [
            json!({"fusion_alpha":0.51,"fusion_beta":0.5}),
            json!({"fusion_alpha":0.76}),
            json!({"fusion_beta":0.81}),
        ] {
            assert_eq!(
                validate(&value).err().map(|error| error.to_string()),
                Some("fusion_alpha + fusion_beta must not exceed 1".to_owned())
            );
        }
        for number in [f32::MIN_POSITIVE as f64, 1.0, 10.0] {
            validate(&json!({"fusion_temperature":number}))?;
        }
        for number in [-1.0, 0.0, 10.01, 1e-100] {
            assert_eq!(
                validate(&json!({"fusion_temperature":number}))
                    .err()
                    .map(|error| error.to_string()),
                Some("invalid recall_fusion setting fusion_temperature".to_owned())
            );
        }
        Ok(())
    }

    #[test]
    fn unknown_settings_and_wrong_json_types_are_rejected() {
        for value in [Value::Null, json!([]), json!("legacy"), json!(true)] {
            assert!(validate(&value).is_err());
        }
        assert!(validate(&json!({"unknown":0.5})).is_err());
        for value in [json!("AUTO"), json!(""), json!(0), Value::Null] {
            assert!(validate(&json!({"fusion":value})).is_err());
        }
        for &(key, _) in NUMERIC {
            for value in [
                json!("0.5"),
                json!(false),
                Value::Null,
                json!([]),
                json!({}),
            ] {
                assert_eq!(
                    validate(&json!({(key):value}))
                        .err()
                        .map(|error| error.to_string()),
                    Some(format!("{key} must be a number"))
                );
            }
        }
    }
}
