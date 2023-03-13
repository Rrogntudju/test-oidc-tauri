use crate::Fournisseur;
use anyhow::{anyhow, Error};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AccessToken, AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
    TokenUrl,
};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::async_runtime::spawn_blocking;
use tauri::{AppHandle, WindowBuilder, WindowUrl};
use url::Url;

pub struct Pkce {
    token: AccessToken,
    creation: Instant,
    expired_in: Duration,
}

impl Pkce {
    pub async fn new(f: &Fournisseur, h: &AppHandle) -> Result<Self, Error> {
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
        let (rx, stop_signal) = start_listening(listener, csrf_state)?;

        let oauth_window = match WindowBuilder::new(h, "oauth2", WindowUrl::External(authorize_url))
            .title(format!("{f}"))
            .inner_size(600., 600.)
            .build()
        {
            Ok(oauth_window) => oauth_window,
            Err(e) => {
                stop_signal.store(true, Ordering::Relaxed);
                return Err(e.into());
            }
        };

        let receive = spawn_blocking(move || match rx.recv() {
            Ok(code) => Ok(code),
            Err(RecvError) => Err(anyhow!("Vous devez vous authentifier")),
        });

        let code_result = receive.await.expect("spawn_blocking error");
        oauth_window.close()?;
        let code = code_result?;

        let creation = Instant::now();
        let token = client.exchange_code(code).set_pkce_verifier(pkce_code_verifier).request_async(async_http_client).await?;
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
    listener.set_nonblocking(true).expect("set_nonblocking a retourné une erreur");

    std::thread::spawn(move || {
        let now = Instant::now();
        while !stop_signal2.load(Ordering::Relaxed) {
            let stream = listener.accept();
            match stream {
                Ok((ref stream, _)) => {
                    let mut request_line = String::new();
                    let mut reader = BufReader::new(stream);
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
                    let code = AuthorizationCode::new(value.into_owned());

                    let state_pair = url
                        .query_pairs()
                        .find(|pair| {
                            let (key, _) = pair;
                            key == "state"
                        })
                        .expect("Le jeton csrf doit être présent");

                    let (_, value) = state_pair;
                    assert_eq!(csrf.secret(), value.as_ref());

                    let _ = tx.send(code);
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if now.elapsed().as_secs() >= 120 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => panic!("accept IO error: {e}"),
            }
        }
    });

    Ok((rx, stop_signal))
}
