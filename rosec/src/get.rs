//! `rosec get <item>` — print the primary secret value (or a named attribute) of an item.

use std::collections::HashMap;

use anyhow::{Result, bail};
use zbus::Connection;
use zvariant::{OwnedObjectPath, OwnedValue};

use crate::cli::GetArgs;
use crate::{conn, preemptive_sync, resolve_item_path, trigger_unlock, try_lazy_unlock};

pub async fn run(args: GetArgs) -> Result<()> {
    let attr = args.attr;
    let sync = args.sync;
    let no_unlock = args.no_unlock;

    if sync && no_unlock {
        bail!("--sync and --no-unlock are mutually exclusive");
    }

    let raw = args.item.as_str();

    let conn = conn().await?;

    if sync {
        preemptive_sync(&conn).await?;
    }

    let resolve_result = resolve_item_path(&conn, raw).await;

    let (path, is_locked) = match resolve_result {
        Ok(result) => result,
        Err(e) if sync && !no_unlock => {
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            resolve_item_path(&conn, raw).await.map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };

    if is_locked {
        if no_unlock {
            bail!("item is locked — use --sync to unlock the provider first");
        }
        trigger_unlock(&conn).await?;
        if sync {
            preemptive_sync(&conn).await?;
        }
    }

    match get_inner(&conn, &path, attr.as_deref()).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let zbus_err = e.downcast_ref::<zbus::Error>();
            if !no_unlock
                && let Some(ze) = zbus_err
                && try_lazy_unlock(&conn, ze).await?
            {
                get_inner(&conn, &path, attr.as_deref()).await
            } else {
                Err(e)
            }
        }
    }
}

/// Normalise an `--attr` value that may use dot-index syntax.
///
/// Any attribute with multiple values uses `name.N` notation in the CLI:
/// - `name`   → `"name"`   (bare = index 0, backwards compat)
/// - `name.0` → `"name"`   (explicit index 0 → bare key)
/// - `name.1` → `"name.1"` (index 1 stored as "name.1")
/// - `name.2` → `"name.2"`, …
///
/// This is generic — it works for `uri`, `custom.field`, or any future
/// multi-value attribute without needing an allowlist.
fn normalise_attr_key(attr: &str) -> String {
    if let Some(dot) = attr.rfind('.') {
        let name = &attr[..dot];
        let suffix = &attr[dot + 1..];
        if !name.is_empty()
            && suffix.chars().all(|c| c.is_ascii_digit())
            && let Ok(idx) = suffix.parse::<usize>()
        {
            return if idx == 0 {
                name.to_string()
            } else {
                format!("{name}.{idx}")
            };
        }
    }
    attr.to_string()
}

async fn get_inner(conn: &Connection, path: &str, attr: Option<&str>) -> Result<()> {
    use std::io::Write;

    if let Some(attr_name) = attr {
        let resolved = normalise_attr_key(attr_name);
        let item_proxy = zbus::Proxy::new(
            conn,
            "org.freedesktop.secrets",
            path,
            "org.freedesktop.Secret.Item",
        )
        .await?;
        let attrs: HashMap<String, String> = item_proxy.get_property("Attributes").await?;
        match attrs.get(resolved.as_str()) {
            Some(v) => {
                let mut out = std::io::stdout();
                out.write_all(v.as_bytes())?;
                if std::io::IsTerminal::is_terminal(&out) && !v.ends_with('\n') {
                    out.write_all(b"\n")?;
                }
                return Ok(());
            }
            None => bail!("attribute '{resolved}' not found on this item"),
        }
    }

    let service_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await?;

    let (_, session_path): (OwnedValue, OwnedObjectPath) = service_proxy
        .call("OpenSession", &("plain", zvariant::Value::from("")))
        .await?;

    let item_path = OwnedObjectPath::try_from(path.to_string())
        .map_err(|e| anyhow::anyhow!("invalid item path: {e}"))?;
    let items = vec![&item_path];
    type SecretTuple = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
    let secrets_result: Result<HashMap<OwnedObjectPath, SecretTuple>, zbus::Error> = service_proxy
        .call("GetSecrets", &(items, &session_path))
        .await;

    let _: () = service_proxy
        .call("CloseSession", &(&session_path,))
        .await?;

    match secrets_result {
        Ok(secrets) if secrets.is_empty() => {
            bail!("no secret found for item");
        }
        Ok(secrets) => {
            if let Some((_item_path, (_session, _params, secret_bytes, _content_type))) =
                secrets.into_iter().next()
            {
                let mut out = std::io::stdout();
                out.write_all(&secret_bytes)?;
                if std::io::IsTerminal::is_terminal(&out) && !secret_bytes.ends_with(b"\n") {
                    out.write_all(b"\n")?;
                }
                return Ok(());
            }
            bail!("no secret found for item");
        }
        Err(zbus::Error::MethodError(_, Some(detail), _))
            if detail.as_str().starts_with("no secret for cipher") =>
        {
            bail!("item has no primary secret");
        }
        Err(e) => Err(e.into()),
    }
}
