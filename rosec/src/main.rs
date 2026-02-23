use std::collections::HashMap;

use anyhow::Result;
use zbus::Connection;
use zvariant::{OwnedObjectPath, OwnedValue};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    match cmd {
        "status" => cmd_status().await,
        "refresh" => cmd_refresh().await,
        "search" => cmd_search(&args[1..]).await,
        "get" => cmd_get(&args[1..]).await,
        "lock" => cmd_lock().await,
        "unlock" => cmd_unlock().await,
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}");
            print_help();
            std::process::exit(1);
        }
    }
}

fn print_help() {
    println!(
        "\
rosec - read-only secret service CLI

USAGE:
    rosec <command> [args...]

COMMANDS:
    status              Show daemon status
    refresh             Force item cache refresh
    search <key=value>  Search items by attributes
    get <path>          Get a secret by item path
    lock                Lock the vault
    unlock              Unlock the vault (triggers prompt)
    help                Show this help"
    );
}

async fn conn() -> Result<Connection> {
    let conn = Connection::session().await?;
    Ok(conn)
}

async fn cmd_status() -> Result<()> {
    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let reply: OwnedValue = proxy.call("Status", &()).await?;
    let (backend_id, backend_name, cache_size, last_refresh, sessions) =
        <(String, String, u32, u64, u32)>::try_from(reply)?;

    println!("Backend:      {backend_name} ({backend_id})");
    println!("Cache size:   {cache_size} items");
    println!("Last refresh: {last_refresh} (epoch secs)");
    println!("Sessions:     {sessions}");
    Ok(())
}

async fn cmd_refresh() -> Result<()> {
    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/rosec/Daemon",
        "org.rosec.Daemon",
    )
    .await?;

    let count: u32 = proxy.call("Refresh", &()).await?;
    println!("Refreshed: {count} items");
    Ok(())
}

async fn cmd_search(args: &[String]) -> Result<()> {
    let mut attrs: HashMap<String, String> = HashMap::new();
    for arg in args {
        if let Some((key, value)) = arg.split_once('=') {
            attrs.insert(key.to_string(), value.to_string());
        } else {
            eprintln!("invalid attribute format: {arg} (expected key=value)");
            std::process::exit(1);
        }
    }

    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    let (unlocked, locked): (Vec<String>, Vec<String>) =
        proxy.call("SearchItems", &(attrs,)).await?;

    if unlocked.is_empty() && locked.is_empty() {
        println!("No items found.");
        return Ok(());
    }
    if !unlocked.is_empty() {
        println!("Unlocked:");
        for path in &unlocked {
            println!("  {path}");
        }
    }
    if !locked.is_empty() {
        println!("Locked:");
        for path in &locked {
            println!("  {path}");
        }
    }
    Ok(())
}

async fn cmd_get(args: &[String]) -> Result<()> {
    let path = args.first().ok_or_else(|| anyhow::anyhow!("missing item path"))?;

    let conn = conn().await?;

    // Open a plain session
    let service_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    let (_, session_path): (OwnedValue, String) = service_proxy
        .call("OpenSession", &("plain", zvariant::Value::from("")))
        .await?;

    // GetSecrets
    let items = vec![path.clone()];
    let secrets: HashMap<String, OwnedValue> = service_proxy
        .call("GetSecrets", &(items, &session_path))
        .await?;

    if secrets.is_empty() {
        println!("No secret returned (item may be locked or not found).");
    } else {
        for (item_path, value) in secrets {
            match <(OwnedObjectPath, Vec<u8>, Vec<u8>, String)>::try_from(value) {
                Ok((_session, _params, secret_bytes, _content_type)) => {
                    let text = String::from_utf8_lossy(&secret_bytes);
                    println!("{item_path}: {text}");
                }
                Err(_) => {
                    println!("{item_path}: <could not decode secret>");
                }
            }
        }
    }

    // Close the session
    let _: () = service_proxy
        .call("CloseSession", &(&session_path,))
        .await?;

    Ok(())
}

async fn cmd_lock() -> Result<()> {
    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    let (locked, _prompt): (Vec<String>, String) = proxy
        .call("Lock", &(vec!["/org/freedesktop/secrets/collection/default"],))
        .await?;

    if locked.is_empty() {
        println!("Lock requested (may require prompt).");
    } else {
        println!("Locked: {} objects", locked.len());
    }
    Ok(())
}

async fn cmd_unlock() -> Result<()> {
    let conn = conn().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    let (unlocked, _prompt): (Vec<String>, String) = proxy
        .call("Unlock", &(vec!["/org/freedesktop/secrets/collection/default"],))
        .await?;

    if unlocked.is_empty() {
        println!("Unlock requested (may require prompt).");
    } else {
        println!("Unlocked: {} objects", unlocked.len());
    }
    Ok(())
}
