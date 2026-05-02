//! `rosec inspect <item>` — print full item metadata + secret value.

use std::collections::HashMap;

use anyhow::Result;
use zbus::Connection;
use zeroize::Zeroizing;
use zvariant::{OwnedObjectPath, OwnedValue};

use crate::cli::InspectArgs;
use crate::{
    OutputFormat, cli_format_to_output, conn, preemptive_sync, resolve_item_path, trigger_unlock,
    try_lazy_unlock,
};

pub async fn run(args: InspectArgs) -> Result<()> {
    let all_attrs = args.all_attrs;
    let sync = args.sync;
    let format = cli_format_to_output(args.format);
    let raw = args.item.as_str();

    let conn = conn().await?;

    if sync {
        preemptive_sync(&conn).await?;
    }

    let (path, is_locked) = match resolve_item_path(&conn, raw).await {
        Ok(result) => result,
        Err(e) => {
            // Item not in cache — trigger unlock (which may populate it) then retry.
            trigger_unlock(&conn).await?;
            preemptive_sync(&conn).await?;
            resolve_item_path(&conn, raw).await.map_err(|_| e)?
        }
    };

    if is_locked {
        trigger_unlock(&conn).await?;
        if sync {
            preemptive_sync(&conn).await?;
        }
    }

    match inspect_inner(&conn, &path, all_attrs, &format).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let zbus_err = e.downcast_ref::<zbus::Error>();
            if let Some(ze) = zbus_err
                && try_lazy_unlock(&conn, ze).await?
            {
                inspect_inner(&conn, &path, all_attrs, &format).await
            } else {
                Err(e)
            }
        }
    }
}

/// Print full item metadata (label, attributes) plus the secret value.
///
/// When `all_attrs` is true, also fetches sensitive attribute names via
/// `org.rosec.Secrets.GetSecretAttributeNames` and their values via
/// `GetSecretAttribute`, displaying them alongside the public attributes.
async fn inspect_inner(
    conn: &Connection,
    path: &str,
    all_attrs: bool,
    format: &OutputFormat,
) -> Result<()> {
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

    let item_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.secrets",
        path,
        "org.freedesktop.Secret.Item",
    )
    .await?;

    let label: String = item_proxy.get_property("Label").await?;
    let pub_attrs: HashMap<String, String> = item_proxy.get_property("Attributes").await?;

    let secret_attrs: Vec<(String, Zeroizing<Vec<u8>>)> = if all_attrs {
        let secrets_proxy = zbus::Proxy::new(
            conn,
            "org.freedesktop.secrets",
            "/org/rosec/Secrets",
            "org.rosec.Secrets",
        )
        .await?;

        let item_obj_path = OwnedObjectPath::try_from(path.to_string())
            .map_err(|e| anyhow::anyhow!("invalid item path: {e}"))?;

        let names: Vec<String> = secrets_proxy
            .call("GetSecretAttributeNames", &(&item_obj_path,))
            .await?;

        let mut pairs: Vec<(String, Zeroizing<Vec<u8>>)> = Vec::with_capacity(names.len());
        for name in names {
            let bytes: Vec<u8> = secrets_proxy
                .call("GetSecretAttribute", &(&item_obj_path, name.as_str()))
                .await
                .unwrap_or_default();
            pairs.push((name, Zeroizing::new(bytes)));
        }
        pairs
    } else {
        Vec::new()
    };

    let inspect_item_path = OwnedObjectPath::try_from(path.to_string())
        .map_err(|e| anyhow::anyhow!("invalid item path: {e}"))?;
    let items = vec![&inspect_item_path];
    type SecretTuple = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
    let secrets_result: Result<HashMap<OwnedObjectPath, SecretTuple>, zbus::Error> = service_proxy
        .call("GetSecrets", &(items, &session_path))
        .await;

    let _: () = service_proxy
        .call("CloseSession", &(&session_path,))
        .await?;

    match format {
        OutputFormat::Human | OutputFormat::Table => {
            println!("Label:      {label}");
            println!("Path:       {path}");

            if !pub_attrs.is_empty() {
                println!("Attributes (public):");
                let mut sorted: Vec<_> = pub_attrs.iter().collect();
                sorted.sort_by_key(|(k, _)| *k);
                for (k, v) in sorted {
                    println!("  {k}: {v}");
                }
            }

            if !secret_attrs.is_empty() {
                println!("Attributes (sensitive):");
                for (k, v) in &secret_attrs {
                    let text = String::from_utf8_lossy(v);
                    println!("  {k}: {text}");
                }
            }

            match secrets_result {
                Ok(secrets) if secrets.is_empty() => {
                    println!("Secret:     <none>");
                }
                Ok(secrets) => {
                    for (_item_path, (_session, _params, secret_bytes, content_type)) in secrets {
                        let text = String::from_utf8_lossy(&secret_bytes);
                        if text.is_empty() {
                            println!("Secret:     <empty>");
                        } else {
                            println!("Secret ({content_type}):");
                            println!("  {text}");
                        }
                    }
                }
                Err(zbus::Error::MethodError(_, Some(detail), _))
                    if detail.as_str().starts_with("no secret for cipher") =>
                {
                    println!("Secret:     <not available — this item type has no primary secret>");
                }
                Err(e) => println!("Secret:     <error: {e}>"),
            }
        }

        OutputFormat::Kv => {
            println!("label={label}");
            println!("path={path}");
            let mut sorted_pub: Vec<_> = pub_attrs.iter().collect();
            sorted_pub.sort_by_key(|(k, _)| *k);
            for (k, v) in sorted_pub {
                println!("{k}={v}");
            }
            for (k, v) in &secret_attrs {
                let text = String::from_utf8_lossy(v);
                println!("{k}={text}");
            }
            if let Ok(secrets) = secrets_result {
                for (_item_path, (_session, _params, secret_bytes, _ct)) in secrets {
                    let text = String::from_utf8_lossy(&secret_bytes);
                    println!("secret={text}");
                }
            }
        }

        OutputFormat::Json => {
            let mut sorted_pub: Vec<_> = pub_attrs.iter().collect();
            sorted_pub.sort_by_key(|(k, _)| *k);

            let pub_obj: serde_json::Map<String, serde_json::Value> = sorted_pub
                .into_iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect();

            let secret_obj: serde_json::Map<String, serde_json::Value> = secret_attrs
                .iter()
                .map(|(k, v)| {
                    let text = String::from_utf8_lossy(v).into_owned();
                    (k.clone(), serde_json::Value::String(text))
                })
                .collect();

            let primary_secret = match secrets_result {
                Ok(secrets) => {
                    let mut val = serde_json::Value::Null;
                    for (_item_path, (_session, _params, secret_bytes, _ct)) in secrets {
                        val = serde_json::Value::String(
                            String::from_utf8_lossy(&secret_bytes).into_owned(),
                        );
                    }
                    val
                }
                Err(_) => serde_json::Value::Null,
            };

            let mut obj = serde_json::Map::new();
            obj.insert("label".into(), serde_json::Value::String(label));
            obj.insert("path".into(), serde_json::Value::String(path.to_string()));
            obj.insert("attributes".into(), serde_json::Value::Object(pub_obj));
            if all_attrs {
                obj.insert(
                    "sensitive_attributes".into(),
                    serde_json::Value::Object(secret_obj),
                );
            }
            obj.insert("secret".into(), primary_secret);

            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Object(obj))?
            );
        }
    }

    Ok(())
}
