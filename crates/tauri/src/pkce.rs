use crate::Fournisseur;
use anyhow::Error;
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::{
    AccessToken, AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
    TokenUrl,
};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::time::{Duration, Instant};
use tauri::{AppHandle, WindowBuilder, WindowUrl};
use url::Url;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::atomic::{AtomicBool, Ordering};

pub struct Pkce {
    token: AccessToken,
    creation: Instant,
    expired_in: Duration,
}

impl Pkce {
    pub fn new(f: &Fournisseur, h: &AppHandle) -> Result<Self, Error> {
        let (id, secret) = f.secrets();
        let id = ClientId::new(id.to_owned());
        let secret = ClientSecret::new(secret.to_owned());

        let (url_auth, url_token) = f.endpoints();
        let url_auth = AuthUrl::new(url_auth.to_owned())?;
        let url_token = TokenUrl::new(url_token.to_owned())?;

        let client = BasicClient::new(id, Some(secret), url_auth, Some(url_token))
            .set_auth_type(AuthType::RequestBody)
            .set_redirect_uri(RedirectUrl::new("http://localhost:86".to_owned())?);

        let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

        let (authorize_url, csrf_state) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_owned()))
            .add_scope(Scope::new("email".to_owned()))
            .add_scope(Scope::new("profile".to_owned()))
            .set_pkce_challenge(pkce_code_challenge)
            .url();

        let listener = TcpListener::bind("[::1]:86")?;


        let _oauth_window = WindowBuilder::new(h, "oauth2", WindowUrl::External(authorize_url))
            .title(format!("{f}"))
            .inner_size(800., 600.)
            .build()?;


        println!("là");
        let creation = Instant::now();
        let token = client.exchange_code(code).set_pkce_verifier(pkce_code_verifier).request(http_client)?;
        let expired_in = token.expires_in().unwrap_or(Duration::from_secs(3600));
        let token = token.access_token().to_owned();
        Ok(Self { token, creation, expired_in })
    }

    pub fn is_expired(&self) -> bool {
        self.creation.elapsed() >= self.expired_in
    }

    pub fn secret(&self) -> &String {
        self.token.secret()
    }
}

fn start_listening(listener: TcpListener, csrf: CsrfToken) -> Result<(Receiver<AuthorizationCode>, Arc<AtomicBool>), Error> {
    let (tx, rx) = sync_channel::<AuthorizationCode>(1);
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_signal2 = stop_signal.clone();
    let listen = listener.incoming().filter_map(Result::ok);

    std::thread::spawn(move || {
        let mut code = AuthorizationCode::new(String::new());

        while !stop_signal2.load(Ordering::Relaxed) {
            let stream = listen.next().unwrap();
            let mut request_line = String::new();
            let mut reader = BufReader::new(&stream);
            reader.read_line(&mut request_line).unwrap();

            let redirect_url = request_line.split_whitespace().nth(1).unwrap();
            let url = Url::parse(&(format!("http://localhost{redirect_url}"))).unwrap();
            let code_pair = url
                .query_pairs()
                .find(|pair| {
                    let (key, _) = pair;
                    key == "code"
                })
                .expect("Le code d'autorisation doit être présent");

            let (_, value) = code_pair;
            code = AuthorizationCode::new(value.into_owned());

            let state_pair = url
                .query_pairs()
                .find(|pair| {
                    let (key, _) = pair;
                    key == "state"
                })
                .expect("Le jeton csrf doit être présent");

            let (_, value) = state_pair;
            assert_eq!(csrf.secret(), value.as_ref());

            tx.send(code);
            return;
        }
    });

    Ok((rx, stop_signal))
}