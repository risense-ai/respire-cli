//! Read the Runtime's existing registry; never infer availability from a version.

use super::{choice, line, t, KeyCode, Line, Value};
use anyhow::{Context, Result};
use respire_protocol::RuntimeRequestScope;
use serde_json::json;

#[derive(Clone)]
pub(super) struct Selection {
    model: String,
    backend: String,
    engine: String,
    variant: Option<String>,
    unchanged: bool,
    scope: RuntimeRequestScope,
}

impl Selection {
    fn from_active(value: &Value, scope: &RuntimeRequestScope) -> Result<Self> {
        let field = |key: &str| {
            value[key]
                .as_str()
                .filter(|value| !value.is_empty())
                .with_context(|| format!("Runtime active selection has no {key}"))
        };
        Ok(Self {
            model: field("model")?.into(),
            backend: field("backend")?.into(),
            engine: field("engine")?.into(),
            variant: value["variant"].as_str().map(str::to_owned),
            unchanged: true,
            scope: scope.clone(),
        })
    }

    pub(super) fn label(&self) -> String {
        format!("{} / {} / {}", self.model, self.backend, self.engine)
    }

    pub(super) fn change_engine(&self, engine: &str, variant: Option<&str>) -> Result<Self> {
        anyhow::ensure!(self.model == "m3" || variant.is_none(),
            "This form selects M3 weights. Use the model profile picker to choose a different profile.");
        let mut choice = self.clone();
        choice.engine = engine.into();
        if let Some(variant) = variant {
            choice.variant = Some(variant.into());
        }
        choice.unchanged = choice.engine == self.engine && choice.variant == self.variant;
        Ok(choice)
    }

    pub(super) fn switch(&self) -> Result<crate::output::ResultEnvelope> {
        crate::model_switch::submit_for_scope(
            json!({
                "model":self.model,"backend":self.backend,"engine":self.engine,"variant":self.variant
            }),
            &self.scope,
        )
    }

    pub(super) fn model(&self) -> &str {
        &self.model
    }

    pub(super) fn unchanged(&self) -> bool {
        self.unchanged
    }
}

pub(super) struct Catalog {
    body: Value,
    scope: RuntimeRequestScope,
}

pub(super) fn catalog() -> Result<Option<Catalog>> {
    let before = crate::net_rpc::health()?;
    let response = crate::net_rpc::rpc_method_with_timeout(
        "model.catalog",
        Vec::new(),
        Some(std::time::Duration::from_secs(4)),
    )?;
    if matches!(
        response["code"].as_str(),
        Some("unknown_method" | "unsupported_method")
    ) {
        return Ok(None);
    }
    anyhow::ensure!(
        response["ok"] == true,
        "{}",
        response["error"]
            .as_str()
            .unwrap_or("Runtime did not return the model catalog")
    );
    let summary = response
        .get("envelope")
        .and_then(|envelope| envelope.get("summary"))
        .filter(|summary| summary.is_object())
        .context("Runtime returned an invalid model catalog")?;
    let scope = crate::net_rpc::request_scope(&before)?;
    let after = crate::net_rpc::request_scope(&crate::net_rpc::health()?)?;
    anyhow::ensure!(
        scope == after,
        "Runtime scope changed while reading the model catalog; reopen the picker"
    );
    Ok(Some(Catalog {
        body: summary.clone(),
        scope,
    }))
}

pub(super) fn active(catalog: &Catalog) -> Result<Option<Selection>> {
    (!catalog.body["active"].is_null())
        .then(|| Selection::from_active(&catalog.body["active"], &catalog.scope))
        .transpose()
}

pub(super) struct Picker {
    rows: Vec<Selection>,
    cursor: usize,
    active: Option<Selection>,
}

impl Picker {
    pub(super) fn new(catalog: &Catalog) -> Result<Self> {
        let models = catalog.body["registry"]["models"]
            .as_object()
            .context("Runtime registry has no model profiles")?;
        let backends = catalog.body["registry"]["backends"]
            .as_object()
            .context("Runtime registry has no backends")?;
        let active = active(catalog)?;
        let mut rows = Vec::new();
        // Registry IDs are sent back intact; source paths, provider endpoints
        // and credentials are never displayed or reconstructed by the picker.
        for (name, model) in models {
            if name.is_empty() || name.chars().any(char::is_control) {
                continue;
            }
            for (id, backend) in backends {
                if id.is_empty() || id.chars().any(char::is_control) {
                    continue;
                }
                let kind = backend["backend"].as_str();
                let weights = model["weights"]["path"].as_str();
                let supports = match kind {
                    Some("onnx") => weights.is_some_and(|path| {
                        model["onnx"].is_object() || path.to_ascii_lowercase().ends_with(".onnx")
                    }),
                    Some("mlx") => weights
                        .is_some_and(|path| path.to_ascii_lowercase().ends_with(".safetensors")),
                    Some("host_transport") => {
                        model["weights"].is_null() && model["tokenizer"].is_null()
                    }
                    _ => false,
                };
                if supports {
                    let current = active
                        .as_ref()
                        .filter(|item| item.model == *name && item.backend == *id);
                    rows.push(current.cloned().unwrap_or_else(|| Selection {
                        model: name.clone(),
                        backend: id.clone(),
                        engine: "cpu".into(),
                        variant: None,
                        unchanged: false,
                        scope: catalog.scope.clone(),
                    }));
                }
            }
        }
        anyhow::ensure!(
            !rows.is_empty(),
            "Runtime has no compatible model profile in its catalog"
        );
        let cursor = active
            .as_ref()
            .and_then(|current| {
                rows.iter().position(|choice| {
                    choice.model == current.model && choice.backend == current.backend
                })
            })
            .unwrap_or(0);
        Ok(Self {
            rows,
            cursor,
            active,
        })
    }

    pub(super) fn key(&mut self, code: KeyCode) -> Option<Selection> {
        match code {
            KeyCode::Up => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Down => self.cursor = (self.cursor + 1).min(self.rows.len() - 1),
            KeyCode::Enter => return self.rows.get(self.cursor).cloned(),
            _ => {}
        }
        None
    }

    pub(super) fn lines(&self) -> Vec<Line<'static>> {
        let mut lines = vec![line(t("Runtime 模型配置", "Runtime model profiles"))];
        let start = self.cursor.saturating_sub(7);
        for (index, selection) in self.rows.iter().enumerate().skip(start).take(8) {
            let active = self.active.as_ref().is_some_and(|current| {
                current.model == selection.model && current.backend == selection.backend
            });
            let label = if active {
                format!("{} ({})", selection.label(), t("当前", "active"))
            } else {
                selection.label()
            };
            lines.push(choice(index == self.cursor, label));
        }
        lines.push(line(t(
            "↑/↓ 选择，回车确认，Esc 返回",
            "Up/down selects, Enter confirms, Esc returns",
        )));
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_picker_uses_registry_ids_for_local_and_configured_remote_profiles() -> Result<()> {
        let body = json!({
            "registry": {"models": {
                "m3":{"weights":{"path":"m3.onnx"}},
                "bge-small":{"weights":{"path":"small.onnx"}},
                "granite":{"weights":{"path":"granite.onnx"}},
                "m3-mlx":{"weights":{"path":"m3.safetensors"}},
                "remote":{"weights":null,"tokenizer":null}
            },"backends":{
                "onnx":{"backend":"onnx"}, "mlx":{"backend":"mlx"},
                "remote-service":{"backend":"host_transport","endpoint":"irrelevant"}
            }},
            "active":{"model":"granite","backend":"onnx","engine":"cpu","variant":null}
        });
        let catalog = Catalog {
            body,
            scope: RuntimeRequestScope {
                account_id: "account".into(),
                instance_id: "instance".into(),
                generation: 8,
            },
        };
        let mut picker = Picker::new(&catalog)?;
        assert_eq!(picker.rows.len(), 5);
        assert!(picker
            .rows
            .iter()
            .all(|selection| selection.scope == catalog.scope));
        assert_eq!(
            picker
                .key(KeyCode::Enter)
                .context("missing choice")?
                .model(),
            "granite"
        );
        assert_eq!(
            picker
                .rows
                .iter()
                .find(|row| row.model == "remote")
                .context("missing remote")?
                .backend,
            "remote-service"
        );
        assert!(active(&catalog)?
            .context("missing active")?
            .change_engine("cpu", Some("fp16"))
            .is_err());
        Ok(())
    }
}
