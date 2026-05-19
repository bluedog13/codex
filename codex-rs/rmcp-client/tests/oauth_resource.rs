use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::WWW_AUTHENTICATE;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Json;
use codex_config::types::OAuthCredentialsStoreMode;
use codex_rmcp_client::perform_oauth_login_return_url;
use reqwest::Url;
use serde_json::json;
use serial_test::serial;
use tokio::sync::Mutex;

#[derive(Clone)]
struct MockOAuthServerState {
    base_url: String,
    token_requests: Arc<Mutex<Vec<String>>>,
}

async fn unauthorized_mcp(
    State(state): State<MockOAuthServerState>,
) -> impl IntoResponse {
    let resource_metadata = format!(
        r#"Bearer resource_metadata="{}/.well-known/oauth-protected-resource/mcp""#,
        state.base_url
    );
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(&resource_metadata).expect("valid WWW-Authenticate header"),
    );
    (StatusCode::UNAUTHORIZED, headers, String::new())
}

async fn protected_resource_metadata(
    State(state): State<MockOAuthServerState>,
) -> Json<serde_json::Value> {
    Json(json!({
        "authorization_server": format!("{}/auth", state.base_url),
    }))
}

async fn authorization_metadata(
    State(state): State<MockOAuthServerState>,
) -> Json<serde_json::Value> {
    Json(json!({
        "authorization_endpoint": format!("{}/authorize", state.base_url),
        "token_endpoint": format!("{}/token", state.base_url),
        "registration_endpoint": format!("{}/register", state.base_url),
        "response_types_supported": ["code"],
    }))
}

async fn register_client() -> Json<serde_json::Value> {
    Json(json!({
        "client_id": "codex-client",
        "redirect_uris": ["http://127.0.0.1/callback"],
    }))
}

async fn exchange_token(
    State(state): State<MockOAuthServerState>,
    body: String,
) -> Json<serde_json::Value> {
    state.token_requests.lock().await.push(body);
    Json(json!({
        "access_token": "access-token",
        "refresh_token": "refresh-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "myscope offline_access",
    }))
}

async fn run_login_flow(resource_override: Option<&str>) -> (String, String, String) {
    run_login_flow_with(resource_override, None).await
}

async fn run_login_flow_with(
    resource_override: Option<&str>,
    oauth_client_id: Option<&str>,
) -> (String, String, String) {
    let token_requests = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let base_url = format!("http://{}", listener.local_addr().expect("listener addr"));
    let state = MockOAuthServerState {
        base_url: base_url.clone(),
        token_requests: Arc::clone(&token_requests),
    };

    let app = Router::new()
        .route("/mcp", get(unauthorized_mcp))
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/auth",
            get(authorization_metadata),
        )
        .route("/register", post(register_client))
        .route("/token", post(exchange_token))
        .with_state(state);
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve mock OAuth server");
    });

    let codex_home = tempfile::tempdir().expect("create temp CODEX_HOME");
    unsafe {
        std::env::set_var(
            "CODEX_HOME",
            codex_home
                .path()
                .to_str()
                .expect("temp CODEX_HOME should be valid utf-8"),
        );
    }

    let server_url = format!("{base_url}/mcp");
    let scopes = vec!["myscope".to_string(), "offline_access".to_string()];
    let handle = perform_oauth_login_return_url(
        "example-mcp",
        &server_url,
        OAuthCredentialsStoreMode::File,
        None,
        None,
        &scopes,
        oauth_client_id,
        resource_override,
        Some(5),
        None,
        None,
    )
    .await
    .expect("start OAuth login");

    let authorization_url = handle.authorization_url().to_string();
    let parsed_authorization_url =
        Url::parse(&authorization_url).expect("authorization URL should parse");
    let state_param = parsed_authorization_url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("authorization URL should include state");
    let redirect_uri = parsed_authorization_url
        .query_pairs()
        .find(|(key, _)| key == "redirect_uri")
        .map(|(_, value)| value.into_owned())
        .expect("authorization URL should include redirect_uri");

    let mut callback_url = Url::parse(&redirect_uri).expect("redirect URI should parse");
    callback_url
        .query_pairs_mut()
        .append_pair("code", "test-code")
        .append_pair("state", &state_param);
    let callback_response = reqwest::Client::new()
        .get(callback_url)
        .send()
        .await
        .expect("send callback request");
    assert_eq!(callback_response.status(), reqwest::StatusCode::OK);

    handle.wait().await.expect("OAuth login should complete");

    let token_request = {
        let requests = token_requests.lock().await;
        assert_eq!(requests.len(), 1);
        requests[0].clone()
    };

    unsafe {
        std::env::remove_var("CODEX_HOME");
    }

    server.abort();

    (server_url, authorization_url, token_request)
}

#[tokio::test]
#[serial(oauth_login_resource)]
async fn oauth_login_includes_server_url_resource_by_default() {
    let (server_url, authorization_url, token_request) = run_login_flow(None).await;
    let parsed_authorization_url =
        Url::parse(&authorization_url).expect("authorization URL should parse");
    let resource = parsed_authorization_url
        .query_pairs()
        .find(|(key, _)| key == "resource")
        .map(|(_, value)| value.into_owned())
        .expect("authorization URL should include resource");

    assert_eq!(resource, server_url);
    let encoded_resource = urlencoding::encode(&server_url);
    assert!(token_request.contains(&format!("resource={encoded_resource}")));
}

#[tokio::test]
#[serial(oauth_login_resource)]
async fn oauth_login_uses_configured_oauth_resource_when_provided() {
    let resource_override = "https://resource.example.com/mcp";
    let (_server_url, authorization_url, token_request) =
        run_login_flow(Some(resource_override)).await;
    let parsed_authorization_url =
        Url::parse(&authorization_url).expect("authorization URL should parse");
    let resource = parsed_authorization_url
        .query_pairs()
        .find(|(key, _)| key == "resource")
        .map(|(_, value)| value.into_owned())
        .expect("authorization URL should include resource");

    // Both the authorization URL and the token-exchange body must carry the
    // override so RFC 8707 strict providers accept the round-trip.
    assert_eq!(resource, resource_override);
    let encoded_override = urlencoding::encode(resource_override);
    assert!(token_request.contains(&format!("resource={encoded_override}")));
}

#[tokio::test]
#[serial(oauth_login_resource)]
async fn oauth_login_combines_configured_client_id_with_resource_override() {
    let resource_override = "https://resource.example.com/mcp";
    let configured_client_id = "configured-client-id";
    let (_server_url, authorization_url, token_request) =
        run_login_flow_with(Some(resource_override), Some(configured_client_id)).await;

    let parsed_authorization_url =
        Url::parse(&authorization_url).expect("authorization URL should parse");

    let auth_resource = parsed_authorization_url
        .query_pairs()
        .find(|(key, _)| key == "resource")
        .map(|(_, value)| value.into_owned())
        .expect("authorization URL should include resource");
    let auth_client_id = parsed_authorization_url
        .query_pairs()
        .find(|(key, _)| key == "client_id")
        .map(|(_, value)| value.into_owned())
        .expect("authorization URL should include client_id");

    // Authorization URL carries both the configured client_id (skipping DCR)
    // and the resource override.
    assert_eq!(auth_client_id, configured_client_id);
    assert_eq!(auth_resource, resource_override);

    // The token exchange must also carry the resource override and the same
    // client_id — otherwise RFC 8707 strict providers reject the request.
    let encoded_override = urlencoding::encode(resource_override);
    assert!(token_request.contains(&format!("resource={encoded_override}")));
    let encoded_client_id = urlencoding::encode(configured_client_id);
    assert!(token_request.contains(&format!("client_id={encoded_client_id}")));
}
