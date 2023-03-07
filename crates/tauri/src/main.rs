// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use once_cell::sync::Lazy;
use reqwest::{Client, Request};
use static_init::dynamic;
use std::time::Duration;
use tauri::AppHandle;

mod pkce;
use pkce::Pkce;

mod fournisseur;
pub use fournisseur::Fournisseur;

#[dynamic]
static mut TOKEN: Option<(Fournisseur, Pkce)> = None;
static CLIENT: Lazy<Client> = Lazy::new(|| Client::builder().timeout(Duration::from_secs(10)).build().unwrap());

#[tauri::command]
async fn get_userinfos(h: AppHandle, f: Fournisseur) -> Result<String, String> {
    let token = TOKEN.read();
    if token.is_some() {
        let (fournisseur, secret) = token.as_ref().unwrap();
        if &f != fournisseur || secret.is_expired() {
            drop(token);
            TOKEN.write().replace((f.to_owned(), Pkce::new(&h, &f).map_err(|e| e.to_string())?));
        }
    } else {
        drop(token);
        TOKEN.write().replace((f.to_owned(), Pkce::new(&h, &f).map_err(|e| e.to_string())?));
    }

    CLIENT
        .get(f.userinfos())
        .header("Authorization", &format!("Bearer {}", TOKEN.read().as_ref().unwrap().1.secret()))
        .send()
        .await
        .text()
        .await
        .map_err(|e| e.to_string())?
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_userinfos])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
