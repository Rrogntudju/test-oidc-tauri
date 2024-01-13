// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use reqwest::Client;
use serde_json::{Map, Value};
use std::sync::OnceLock;
use std::time::Duration;
use tauri::{command, AppHandle};

mod pkce;
use pkce::Pkce;

mod fournisseur;
pub use fournisseur::Fournisseur;

static TOKEN: OnceLock<Option<(Fournisseur, Pkce)>> = OnceLock::new();
static CLIENT: OnceLock<Client> = OnceLock::new();
static LOL_MAP: OnceLock<Map<String, Value>> = OnceLock::new();

#[command]
async fn get_userinfos(f: Fournisseur, h: AppHandle) -> Result<String, String> {
    let token = TOKEN.get_or_init(|| None);
    if token.is_some() {
        let (fournisseur, secret) = token.as_ref().unwrap();
        if &f != fournisseur || secret.is_expired() {
            let _ = TOKEN.set(Some((f.to_owned(), Pkce::new(&f, &h).await.map_err(|e| format!("{e:#}"))?)));
        }
    } else {
        let _ = TOKEN.set(Some((f.to_owned(), Pkce::new(&f, &h).await.map_err(|e| format!("{e:#}"))?)));
    }

    let userinfos = CLIENT
        .get_or_init(|| Client::builder().timeout(Duration::from_secs(10)).build().unwrap())
        .get(f.userinfos())
        .header("Authorization", format!("Bearer {}", token.as_ref().unwrap().1.secret()))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<Value>()
        .await
        .map_err(|e| e.to_string())?;

    let map = userinfos.as_object().unwrap_or(LOL_MAP.get_or_init(|| Map::default()));
    let userinfos = map
        .iter()
        .map(|(k, v)| {
            let mut map = Map::new();
            map.insert("propriété".into(), Value::String(k.to_owned()));
            map.insert("valeur".into(), v.to_owned());
            Value::Object(map)
        })
        .collect::<Vec<Value>>();

    Ok(serde_json::to_string(&userinfos).unwrap_or_default())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_userinfos])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
