//! `rosec provider kinds` — list available provider kinds with their options.

use rosec_core::{WasmPreference, config_edit};

pub fn run() {
    println!("Available provider kinds:\n");
    println!("  local");
    println!("    A local encrypted vault file on disk.");
    println!("    Options: --id <id>, --path <path>, --collection <name>");
    println!();
    for kind in config_edit::KNOWN_KINDS {
        // "local" is already printed above with its custom description.
        if *kind == "local" {
            continue;
        }
        let required = config_edit::required_options_for_kind(kind);
        let optional = config_edit::optional_options_for_kind(kind);
        println!("  {kind}");
        if !required.is_empty() {
            println!("    Required:");
            for (key, desc) in required {
                println!("      {key:<20}  {desc}");
            }
        }
        if !optional.is_empty() {
            println!("    Optional:");
            for (key, desc) in optional {
                println!("      {key:<20}  {desc}");
            }
        }
        println!();
    }

    let registry = rosec_wasm::discovery::scan_plugins(
        WasmPreference::default(),
        rosec_core::WasmVerify::default(),
    );
    for kind in registry.kinds() {
        let plugin = registry
            .get(kind)
            .expect("kind from registry.kinds() must exist");
        println!("  {kind}");
        println!("    {}", plugin.manifest.description);
        if !plugin.manifest.required_options.is_empty() {
            println!("    Required:");
            for opt in &plugin.manifest.required_options {
                println!("      {:<20}  {}", opt.key, opt.description);
            }
        }
        if !plugin.manifest.optional_options.is_empty() {
            println!("    Optional:");
            for opt in &plugin.manifest.optional_options {
                println!("      {:<20}  {}", opt.key, opt.description);
            }
        }
        println!();
    }
}
