use crate::Fournisseur;
use anyhow::Error;
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::{
    AccessToken, AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
    TokenUrl,
};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};
use url::Url;

pub struct Pkce {
    token: AccessToken,
    creation: Instant,
    expired_in: Duration,
}

impl Pkce {
    pub fn new(f: &Fournisseur) -> Result<Self, Error> {
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
        webbrowser::open(authorize_url.as_ref())?;

        let mut code = AuthorizationCode::new(String::new());
        if let Some(mut stream) = listener.incoming().flatten().next() {
            let mut request_line = String::new();
            let mut reader = BufReader::new(&stream);
            reader.read_line(&mut request_line)?;

            let redirect_url = request_line.split_whitespace().nth(1).unwrap();
            let url = Url::parse(&(format!("http://localhost{redirect_url}")))?;
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
            assert_eq!(csrf_state.secret(), value.as_ref());

            let message = "<p>Retournez dans l'application &#128526;</p>";
            let response = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{message}", message.len());
            stream.write_all(response.as_bytes())?;
        }

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
