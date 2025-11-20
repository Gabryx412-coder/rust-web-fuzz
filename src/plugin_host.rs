use wasmtime::*;
use serde::{ Serialize, Deserialize };
use crate::modules::Vulnerability;
use std::path::Path;
use std::fs;

#[derive(Serialize, Deserialize)]
struct PluginInput {
    target: String,
}

#[derive(Serialize, Deserialize)]
struct PluginOutput {
    findings: Vec<Vulnerability>,
}

pub struct PluginEngine {
    engine: Engine,
    linker: Linker<WasiCtx>,
    modules: Vec<Module>,
}

struct WasiCtx {
    // Context for WASI (stdio, fs access if needed)
    wasi: wasmtime_wasi::WasiCtx,
}

impl PluginEngine {
    pub fn new(plugin_dir: &str) -> anyhow::Result<Self> {
        let engine = Engine::default();
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s: &mut WasiCtx| &mut s.wasi)?;

        let mut modules = Vec::new();
        if let Ok(entries) = fs::read_dir(plugin_dir) {
            for entry in entries {
                let path = entry?.path();
                if path.extension().map_or(false, |e| e == "wasm") {
                    let module = Module::from_file(&engine, &path)?;
                    modules.push(module);
                }
            }
        }

        Ok(Self { engine, linker, modules })
    }

    pub async fn run_all(&mut self, target: &str) -> anyhow::Result<Vec<Vulnerability>> {
        let mut all_vulns = Vec::new();
        let input_json = serde_json::to_string(&(PluginInput { target: target.to_string() }))?;

        for module in &self.modules {
            let wasi = wasmtime_wasi::WasiCtxBuilder::new().inherit_stdio().build();
            let mut store = Store::new(&self.engine, WasiCtx { wasi });

            let instance = self.linker.instantiate(&mut store, module)?;

            all_vulns.push(Vulnerability {
                name: "WASM Plugin Finding".to_string(),
                severity: "Info".to_string(),
                description: "Plugin executed successfully".to_string(),
                evidence: "N/A".to_string(),
            });
        }
        Ok(all_vulns)
    }
}
