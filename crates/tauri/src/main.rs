// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use once_cell::sync::Lazy;
use reqwest::Client;
use serde_json::{Map, Value};
use std::time::Duration;
use tauri::async_runtime::RwLock;
use tauri::AppHandle;

mod pkce;
use pkce::Pkce;

mod fournisseur;
pub use fournisseur::Fournisseur;

static TOKEN: Lazy<RwLock<Option<(Fournisseur, Pkce)>>> = Lazy::new(|| RwLock::new(None));
static CLIENT: Lazy<Client> = Lazy::new(|| Client::builder().timeout(Duration::from_secs(10)).build().unwrap());
static LOL_MAP: Lazy<Map<String, Value>> = Lazy::new(|| Map::default());

#[tauri::command]
async fn get_userinfos(f: Fournisseur, h: AppHandle) -> Result<String, String> {
    let token = TOKEN.read().await;
    if token.is_some() {
        let (fournisseur, secret) = token.as_ref().unwrap();
        if &f != fournisseur || secret.is_expired() {
            let mut token = TOKEN.write().await;
            token.replace((f.to_owned(), Pkce::new(&f, &h).map_err(|e| e.to_string())?));
        }
    } else {
        let mut token = TOKEN.write().await;
        token.replace((f.to_owned(), Pkce::new(&f, &h).map_err(|e| e.to_string())?));
    }

    let userinfos = CLIENT
        .get(f.userinfos())
        .header("Authorization", format!("Bearer {}", token.as_ref().unwrap().1.secret()))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<Value>()
        .await
        .map_err(|e| e.to_string())?;

    let map = userinfos.as_object().unwrap_or(&LOL_MAP);
    let userinfos = map
        .iter()
        .filter_map(|(k, v)| {
            let mut map = Map::new();
            map.insert("propriété".into(), Value::String(k.to_owned()));
            map.insert("valeur".into(), v.to_owned());
            Some(Value::Object(map))
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
