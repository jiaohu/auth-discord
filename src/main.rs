use axum::{
    extract::{Extension, Query},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::{get, Router},
    serve,
};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, RevocationUrl, TokenResponse, TokenUrl
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::{Arc, Mutex}};
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

extern crate dotenv;
use dotenv::dotenv;
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
pub(crate) struct DiscordCallBackParams {
    pub(crate) code: AuthorizationCode,
    pub(crate) state: CsrfToken,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct DiscordUser {
    id: String,
    username: String,
}

#[derive(Clone, Debug)]
pub struct DiscordOauth2Client(BasicClient);

pub struct DiscordOauth2Ctx {
    pub(crate) client: DiscordOauth2Client,
}

impl DiscordOauth2Client {
    pub fn new(
        client_id: impl ToString,
        client_secret: impl ToString,
        callback_url: impl ToString,
    ) -> Self {
        Self(
            BasicClient::new(
                ClientId::new(client_id.to_string()),
                Some(ClientSecret::new(client_secret.to_string())),
                AuthUrl::new("https://discord.com/oauth2/authorize".to_string()).unwrap(),
                Some(TokenUrl::new("https://discord.com/api/oauth2/token".to_string()).unwrap()),
            )
            .set_revocation_uri(
                RevocationUrl::from_url(
                    "https://discord.com/api/oauth2/token/revoke"
                        .parse()
                        .unwrap(),
                )
            )
            .set_redirect_uri(RedirectUrl::new(callback_url.to_string()).unwrap()),
        )
    }
}

#[derive(Debug, Error)]
pub(crate) enum CallbackError {
    #[error("No previous state found")]
    NoPreviousState,
    #[error("Invalid state returned")]
    InvalidState,
    #[error("No PKCE verifier found")]
    NoVerifierFound,
    #[error("Internal server error: {0}")]
    InternalServerError(String),
}

impl IntoResponse for CallbackError {
    fn into_response(self) -> axum::response::Response {
        let status_code = match self {
            CallbackError::NoPreviousState => StatusCode::INTERNAL_SERVER_ERROR,
            CallbackError::InvalidState => StatusCode::BAD_REQUEST,
            CallbackError::NoVerifierFound => StatusCode::INTERNAL_SERVER_ERROR,
            CallbackError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status_code, self.to_string()).into_response()
    }
}

async fn login(Extension(ctx): Extension<Arc<AsyncMutex<DiscordOauth2Ctx>>>) -> Redirect {
    let ctx = ctx.lock().await;
    let (url, _state) = ctx
        .client
        .0
        .authorize_url(CsrfToken::new_random)
        .add_scopes(vec![oauth2::Scope::new("identify".to_string())])
        .url();

    Redirect::temporary(&url.to_string())
}

async fn oauth_discord(
    Query(params): Query<DiscordCallBackParams>,
    Extension(ctx): Extension<Arc<AsyncMutex<DiscordOauth2Ctx>>>,
) -> impl IntoResponse {
    dotenv().ok();
    let client = {
        let ctx = ctx.lock().await;
        ctx.client.clone()
    };

    let token_result = client
        .0
        .exchange_code(params.code)
        .request_async(async_http_client)
        .await
        .map_err(|e| CallbackError::InternalServerError(e.to_string())).unwrap();

    let access_token = token_result.access_token().secret();
    println!("{}", access_token);

    let user_info: DiscordUser = Client::new()
        .get("https://discord.com/api/users/@me")
        .bearer_auth(access_token)
        .send()
        .await.map_err(|e| CallbackError::InternalServerError(e.to_string())).unwrap()
        .json()
        .await
        .map_err(|e| CallbackError::InternalServerError(e.to_string())).unwrap();


    (StatusCode::OK, format!("User info: {:?}", user_info))
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "oauth2_callback=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let addr = SocketAddr::from(([127, 0, 0, 1], 8088));
    let discord_ctx = DiscordOauth2Ctx {
        client: DiscordOauth2Client::new(
            std::env::var("DISCORD_CLIENT_ID").unwrap(),
            std::env::var("DISCORD_CLIENT_SECRET").unwrap(),
            "http://127.0.0.1:8088/discord/callback",
        ),
    };

    let shared_ctx = Arc::new(AsyncMutex::new(discord_ctx));

    let app = Router::new()
        .route("/login", get(login))
        .route("/discord/callback", get(oauth_discord))
        .layer(Extension(shared_ctx));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8088").await.unwrap();
    println!("\nOpen http://{}/login in your browser\n", addr);
    tracing::debug!("Serving at {}", addr);

    serve(listener, app).await.unwrap();
}
