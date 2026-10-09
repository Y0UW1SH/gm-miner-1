//! Exercise worker removal through the CLI, including persisted state and guidance.

#![expect(clippy::expect_used, reason = "test fixtures and assertions")]

use serde_json::{json, Value};
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, ResponseTemplate,
};

const WORKER_ID: &str = "01J0C";
const WORKER_PATH: &str = "/miners/5HK/workers/01J0C";
const LIST_PATH: &str = "/miners/5HK/workers";

fn config(server: &MockServer) -> Value {
    let worker = json!({
        "worker_id": WORKER_ID, "app_name": "miner-two", "app_id": "app_two",
        "node_secret": "worker-secret"
    });
    let initial = json!({
        "active_network": "testnet",
        "networks": {
            "testnet": {
                "api_url": server.uri(),
                "tokens": {"access_token": "test-token", "token_expires_at": "2999-01-01T00:00:00Z"},
                "workers": [
                    {"worker_id": "01J0A", "app_name": "miner-one", "app_id": "app_one", "node_secret": "other-secret"},
                    worker.clone()
                ]
            },
            "mainnet": {"workers": [worker]}
        }
    });
    let config: gm_miner_cli::config::Config =
        serde_json::from_value(initial).expect("valid config");
    serde_json::to_value(config).expect("canonical config")
}

async fn registry(delete: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/miners/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hotkey": "5HK", "status": "active", "products": []
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(WORKER_PATH))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(delete)
        .mount(&server)
        .await;
    server
}

async fn run(initial: &Value, id: &str) -> (std::process::Output, Value) {
    let dir = tempfile::tempdir().expect("temporary config");
    let file = dir.path().join("config.json");
    std::fs::write(
        &file,
        serde_json::to_vec(initial).expect("serialize config"),
    )
    .expect("write config");
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_gmcli"))
        .kill_on_drop(true)
        .env("GMCLI_CONFIG_DIR", dir.path())
        .env_remove("GM_REGISTRY_URL")
        .args(["worker", "remove", id])
        .output()
        .await
        .expect("run CLI");
    let saved =
        serde_json::from_slice(&std::fs::read(file).expect("read config")).expect("parse config");
    (output, saved)
}

fn assert_removed(initial: &Value, output: &std::process::Output, saved: &Value) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let workers = saved["networks"]["testnet"]["workers"]
        .as_array()
        .expect("workers");
    assert_eq!(workers.len(), 1);
    assert_eq!(workers[0]["worker_id"], "01J0A");
    assert!(workers.iter().all(|w| w["app_name"] != "miner-two"));
    assert_eq!(saved["networks"]["mainnet"], initial["networks"]["mainnet"]);
    assert_eq!(
        saved["networks"]["testnet"]["tokens"],
        initial["networks"]["testnet"]["tokens"]
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("phala cvms delete app_two"));
}

#[tokio::test]
async fn confirmed_absence_removes_local_record_by_each_identifier() {
    let server =
        registry(ResponseTemplate::new(404).set_body_json(json!({"error": "worker_not_found"})))
            .await;
    Mock::given(method("GET"))
        .and(path(LIST_PATH))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"workers": []})))
        .mount(&server)
        .await;
    let initial = config(&server);
    for id in [WORKER_ID, "app_two", "miner-two"] {
        let (output, saved) = run(&initial, id).await;
        assert_removed(&initial, &output, &saved);
        assert!(String::from_utf8_lossy(&output.stdout).contains("already absent"));
        let (repeated, unchanged) = run(&saved, WORKER_ID).await;
        assert!(repeated.status.success());
        assert_eq!(unchanged, saved);
        assert!(String::from_utf8_lossy(&repeated.stdout).contains("phala cvms delete <app_id>"));
    }
}

#[tokio::test]
async fn successful_delete_still_removes_without_a_list_request() {
    let server = registry(ResponseTemplate::new(204)).await;
    Mock::given(method("GET"))
        .and(path(LIST_PATH))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let initial = config(&server);
    let (output, saved) = run(&initial, WORKER_ID).await;
    assert_removed(&initial, &output, &saved);
}

#[tokio::test]
async fn ambiguous_absence_keeps_local_state() {
    let responses = [
        ResponseTemplate::new(404),
        ResponseTemplate::new(403),
        ResponseTemplate::new(500),
        ResponseTemplate::new(200).set_body_string("invalid JSON"),
        ResponseTemplate::new(200).set_body_json(json!({})),
        ResponseTemplate::new(200).set_body_json(json!({"workers": [{
            "worker_id": WORKER_ID, "endpoint": "https://worker.example", "status": "active"
        }]})),
    ];
    for response in responses {
        let server = registry(ResponseTemplate::new(404)).await;
        Mock::given(method("GET"))
            .and(path(LIST_PATH))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let initial = config(&server);
        let (output, saved) = run(&initial, WORKER_ID).await;
        assert!(!output.status.success());
        assert_eq!(saved, initial);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("phala cvms delete"));
    }
}

#[tokio::test]
async fn other_delete_failures_keep_local_state_without_confirming_absence() {
    for status in [401, 403, 409, 500] {
        let server = registry(
            ResponseTemplate::new(status).set_body_json(json!({"error": "worker_not_found"})),
        )
        .await;
        Mock::given(method("GET"))
            .and(path(LIST_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"workers": []})))
            .expect(0)
            .mount(&server)
            .await;
        let initial = config(&server);
        let (output, saved) = run(&initial, WORKER_ID).await;
        assert!(!output.status.success());
        assert_eq!(saved, initial);
    }
}

#[tokio::test]
async fn provisional_removal_keeps_cleanup_guidance_without_registry_calls() {
    let server = MockServer::start().await;
    let mut initial = config(&server);
    initial["networks"]["testnet"]["workers"][1]["worker_id"] = json!("");
    let (output, saved) = run(&initial, "miner-two").await;
    assert_removed(&initial, &output, &saved);
    assert!(server
        .received_requests()
        .await
        .expect("requests")
        .is_empty());
}
