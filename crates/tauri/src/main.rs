// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use once_cell::sync::Lazy;
use reqwest::Client;
use std::time::Duration;
use tauri::AppHandle;
use tauri::async_runtime::RwLock;

mod pkce;
use pkce::Pkce;

mod fournisseur;
pub use fournisseur::Fournisseur;

static TOKEN: Lazy<RwLock<Option<(Fournisseur, Pkce)>>> = Lazy::new(|| RwLock::new(None));
static CLIENT: Lazy<Client> = Lazy::new(|| Client::builder().timeout(Duration::from_secs(10)).build().unwrap());

#[tauri::command]
async fn get_userinfos(h: AppHandle, f: Fournisseur) -> Result<String, String> {
    let token = TOKEN.read().await;
    if token.is_some() {
        let (fournisseur, secret) = token.as_ref().unwrap();
        if &f != fournisseur || secret.is_expired() {
            let mut token = TOKEN.write().await;
            token.replace((f.to_owned(), Pkce::new(&h, &f).map_err(|e| e.to_string())?));
        }
    } else {
        let mut token = TOKEN.write().await;
        token.replace((f.to_owned(), Pkce::new(&h, &f).map_err(|e| e.to_string())?));
    }

    let response = CLIENT
        .get(f.userinfos())
        .header("Authorization", &format!("Bearer {}", token.as_ref().unwrap().1.secret()))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;

    Ok(response)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_userinfos])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
