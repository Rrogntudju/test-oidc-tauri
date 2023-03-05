// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use static_init::dynamic;

mod pkce;
use pkce::Pkce;

mod fournisseur;
pub use fournisseur::Fournisseur;

#[dynamic]
static mut TOKEN: Option<(Fournisseur, Pkce)> = None;

#[tauri::command]
async fn get_userinfos(fournisseur: &str) -> Result<String, String> {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_userinfos])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
