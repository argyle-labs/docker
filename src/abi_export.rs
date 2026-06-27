// The tool surface crosses this FFI boundary as opaque JSON — the designated
// JSON dispatch seam, identical to orca's `plugin-loader`. The payload type is
// aliased (`sj`) at this one seam and the workspace disallowed-types lint is
// suppressed for this file only.
#![allow(clippy::disallowed_types)]

//! ABI-stable cdylib export. Builds + exports the single `PluginModRef` root
//! module orca's `plugin-loader` `dlopen`s. Only the entrypoint + metadata
//! cross as `StableAbi` types; the tool surface crosses as JSON.

use std::sync::Arc;
use std::sync::OnceLock;

use abi_stable::export_root_module;
use abi_stable::prefix_type::PrefixTypeTrait;
use abi_stable::std_types::{RErr, ROk, RResult, RStr, RString};
use plugin_toolkit::abi::{PluginMod, PluginModRef, ToolDef};
use plugin_toolkit::contract::config::{Config, Model, Ports};
use plugin_toolkit::contract::ToolCtx;
use plugin_toolkit::dispatch::{dispatch, tool_manifest_json};
use plugin_toolkit::serde_json as sj;
use plugin_toolkit::tokio::runtime::{Builder, Runtime};

extern "C" fn plugin_semver() -> RString {
    RString::from(env!("CARGO_PKG_VERSION"))
}

extern "C" fn target_software() -> RString {
    RString::from("docker")
}

extern "C" fn target_compat() -> RString {
    RString::from(">=20.10")
}

extern "C" fn orca_compat() -> RString {
    RString::from(">=0.0.8, <0.1.0")
}

/// Tool-name prefix this plugin owns. The cdylib statically links the toolkit's
/// domain crates (containers / …), whose `#[orca_tool]` inventory entries the
/// raw `tool_manifest_json()` walk also returns; this plugin exposes only its
/// own `docker.*` namespace across the ABI.
const TOOL_PREFIX: &str = "docker.";

fn own_tools() -> Vec<ToolDef> {
    let all: Vec<ToolDef> = sj::from_str(&tool_manifest_json()).unwrap_or_default();
    all.into_iter()
        .filter(|d| d.name.starts_with(TOOL_PREFIX))
        .collect()
}

extern "C" fn manifest() -> RString {
    let defs = own_tools();
    RString::from(sj::to_string(&defs).unwrap_or_else(|_| "[]".to_string()))
}

fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build plugin tokio runtime")
    })
}

fn minimal_ctx() -> ToolCtx {
    let config = Config {
        anthropic_api_key: None,
        lmstudio_url: String::new(),
        ollama_url: String::new(),
        default_model: Model::LMStudio {
            id: String::new(),
            url: String::new(),
        },
        app_dir: std::env::temp_dir(),
        memory_root: std::env::temp_dir(),
        db_path: std::env::temp_dir().join("orca-plugin.db"),
        ports: Ports::default(),
    };
    ToolCtx::new(Arc::new(config))
}

extern "C" fn invoke(name: RStr<'_>, args_json: RStr<'_>) -> RResult<RString, RString> {
    if !name.as_str().starts_with(TOOL_PREFIX) {
        return RErr(RString::from(format!(
            "tool '{}' is not in this plugin's '{TOOL_PREFIX}' namespace",
            name.as_str()
        )));
    }
    let args: sj::Value = match sj::from_str(args_json.as_str()) {
        Ok(v) => v,
        Err(e) => return RErr(RString::from(format!("invalid args JSON: {e}"))),
    };
    let ctx = minimal_ctx();
    let result = runtime().block_on(dispatch(name.as_str(), args, &ctx));
    match result {
        Ok(value) => match sj::to_string(&value) {
            Ok(s) => ROk(RString::from(s)),
            Err(e) => RErr(RString::from(format!("failed to encode result: {e}"))),
        },
        Err(e) => RErr(RString::from(format!("{e:#}"))),
    }
}

#[export_root_module]
fn export() -> PluginModRef {
    PluginMod {
        plugin_semver,
        target_software,
        target_compat,
        orca_compat,
        manifest,
        invoke,
    }
    .leak_into_prefix()
}
