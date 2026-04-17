use std::path::Path as FsPath;
use std::sync::{Arc, Mutex};

use assert_cmd::Command;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, patch, post},
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use strong_box::StrongBox;
use tempfile::TempDir;
use tokio::net::TcpListener;
use uuid::Uuid;
use worklist_client_auth::Credentials;
use worklist_client_crypto::{
    CommentPayloadBody, SealedPayload, StrongBoxKeyRing, SymmetricKey, TaskPayloadBody,
    USER_DATA_KEY_CONTEXT, WORK_LIST_MEMBERSHIP_CONTEXT, WORK_LIST_PAYLOAD_CONTEXT,
    build_comment_payload_envelope, build_task_payload_envelope, compute_payload_proof,
    decrypt_comment_payload, decrypt_task_payload, derive_payload_binding_key,
    encrypt_comment_payload, encrypt_task_payload, plaintext_rich_text, seal_text_value,
    serialize_to_cbor,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_proven_flows_round_trip_through_mock_api() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state.clone()).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let inspect_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "inspect",
            &fixture.work_list_id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        inspect_output.status.success(),
        "inspect failed: {}",
        inspect_output.stderr
    );
    assert!(
        inspect_output
            .stdout
            .contains("\"title\": \"Fixture Work List\"")
    );

    let create_task_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "tasks",
            "create",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--input-file",
            write_json_file(
                home.path(),
                "task-create.json",
                &json!({
                    "title": "Created from test",
                    "body": "Created body"
                }),
            )
            .to_str()
            .expect("utf8 path"),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        create_task_output.status.success(),
        "task create failed: {}",
        create_task_output.stderr
    );

    let update_task_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "tasks",
            "update",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--title",
            "Updated title",
            "--body",
            "Updated body",
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        update_task_output.status.success(),
        "task update failed: {}",
        update_task_output.stderr
    );

    let create_comment_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "comments",
            "create",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--body",
            "New comment",
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        create_comment_output.status.success(),
        "comment create failed: {}",
        create_comment_output.stderr
    );

    let update_comment_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "comments",
            "update",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--comment-id",
            &fixture.comment_id.to_string(),
            "--body",
            "Updated comment",
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        update_comment_output.status.success(),
        "comment update failed: {}",
        update_comment_output.stderr
    );

    let state = state.lock().expect("state lock");
    let created_task = state
        .created_task_body
        .as_ref()
        .expect("created task body recorded");
    assert_eq!(created_task.title, "Created from test");

    let updated_task = state
        .updated_task_body
        .as_ref()
        .expect("updated task body recorded");
    assert_eq!(updated_task.title, "Updated title");
    assert_eq!(
        updated_task
            .checklist
            .as_ref()
            .expect("checklist preserved")
            .len(),
        1
    );
    assert_eq!(
        updated_task
            .attachments
            .as_ref()
            .expect("attachments preserved")
            .len(),
        1
    );
    assert_eq!(
        updated_task.mentions.as_ref().expect("mentions preserved")[0],
        fixture.mentioned_user_id.to_string()
    );

    let created_comment = state
        .created_comment_body
        .as_ref()
        .expect("created comment body recorded");
    assert_eq!(created_comment.content.blocks[0].text, "New comment");

    let updated_comment = state
        .updated_comment_body
        .as_ref()
        .expect("updated comment body recorded");
    assert_eq!(updated_comment.content.blocks[0].text, "Updated comment");
    assert_eq!(
        updated_comment
            .mentions
            .as_ref()
            .expect("comment mentions preserved")[0],
        fixture.mentioned_user_id.to_string()
    );
    assert_eq!(
        updated_comment
            .attachments
            .as_ref()
            .expect("comment attachments preserved")
            .len(),
        1
    );
    assert_eq!(
        updated_comment
            .client_meta
            .as_ref()
            .expect("comment client meta preserved")["source"],
        "fixture"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_task_reads_parse_current_api_shapes() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let my_tasks_output = run_cli(
        home.path(),
        &server.base_url,
        &["tasks", "list", "--all"],
        None,
    );
    assert!(
        my_tasks_output.status.success(),
        "my tasks failed: {}",
        my_tasks_output.stderr
    );
    assert!(
        my_tasks_output
            .stdout
            .contains(&fixture.task_id.to_string())
    );

    let list_tasks_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "tasks",
            "list",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
        ],
        None,
    );
    assert!(
        list_tasks_output.status.success(),
        "list tasks failed: {}",
        list_tasks_output.stderr
    );
    assert!(
        list_tasks_output
            .stdout
            .contains(&fixture.task_id.to_string())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_tasks_help_uses_explicit_verbs() {
    let output = run_cli(
        TempDir::new().expect("temp home").path(),
        "https://worklist.app",
        &["tasks", "--help"],
        None,
    );

    assert!(
        output.status.success(),
        "tasks help failed: {}",
        output.stderr
    );
    assert!(output.stdout.contains("list"));
    assert!(output.stdout.contains("create"));
    assert!(output.stdout.contains("update"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_rejects_input_stdin_with_password_stdin() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "comments",
            "create",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--input-stdin",
            "--password-stdin",
        ],
        Some(r#"{"body":"hello"}"#),
    );

    assert!(!output.status.success(), "command unexpectedly succeeded");
    assert!(
        output
            .stderr
            .contains("--input-stdin cannot be combined with --password-stdin")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_unlock_daemon_enables_later_decrypt_without_password_flag() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let unlock_output = run_cli(
        home.path(),
        &server.base_url,
        &["auth", "unlock", "--ttl-seconds", "300", "--password-stdin"],
        Some(&fixture.password),
    );
    assert!(
        unlock_output.status.success(),
        "unlock failed: {}",
        unlock_output.stderr
    );

    let inspect_output = run_cli(
        home.path(),
        &server.base_url,
        &["inspect", &fixture.work_list_id.to_string()],
        None,
    );
    assert!(
        inspect_output.status.success(),
        "inspect without password flag failed: {}",
        inspect_output.stderr
    );
    assert!(
        inspect_output
            .stdout
            .contains("\"title\": \"Fixture Work List\"")
    );

    let lock_output = run_cli(home.path(), &server.base_url, &["auth", "lock"], None);
    assert!(
        lock_output.status.success(),
        "lock failed: {}",
        lock_output.stderr
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_logout_locks_daemon() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let unlock_output = run_cli(
        home.path(),
        &server.base_url,
        &["auth", "unlock", "--ttl-seconds", "300", "--password-stdin"],
        Some(&fixture.password),
    );
    assert!(
        unlock_output.status.success(),
        "unlock failed: {}",
        unlock_output.stderr
    );

    let logout_output = run_cli(home.path(), &server.base_url, &["auth", "logout"], None);
    assert!(
        logout_output.status.success(),
        "logout failed: {}",
        logout_output.stderr
    );

    let status_output = run_cli(home.path(), &server.base_url, &["auth", "status"], None);
    assert!(
        status_output.status.success(),
        "status failed: {}",
        status_output.stderr
    );
    assert!(status_output.stdout.contains("Unlock daemon: inactive"));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_unlock_creates_user_only_socket_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let unlock_output = run_cli(
        home.path(),
        &server.base_url,
        &["auth", "unlock", "--ttl-seconds", "300", "--password-stdin"],
        Some(&fixture.password),
    );
    assert!(
        unlock_output.status.success(),
        "unlock failed: {}",
        unlock_output.stderr
    );

    let socket_path = home.path().join(".worklist").join("unlock.sock");
    let mode = std::fs::metadata(&socket_path)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    let _ = run_cli(home.path(), &server.base_url, &["auth", "lock"], None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_status_reports_stored_session_daemon_state_when_api_url_differs() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let unlock_output = run_cli(
        home.path(),
        &server.base_url,
        &["auth", "unlock", "--ttl-seconds", "300", "--password-stdin"],
        Some(&fixture.password),
    );
    assert!(
        unlock_output.status.success(),
        "unlock failed: {}",
        unlock_output.stderr
    );

    let status_output = run_cli(
        home.path(),
        "https://worklist.app",
        &["auth", "status"],
        None,
    );
    assert!(
        status_output.status.success(),
        "status failed: {}",
        status_output.stderr
    );
    assert!(status_output.stdout.contains("Stored:"));
    assert!(
        status_output
            .stdout
            .contains("Current: https://worklist.app")
    );
    assert!(status_output.stdout.contains("Unlock daemon: active"));

    let _ = run_cli(home.path(), &server.base_url, &["auth", "lock"], None);
}

struct TestServer {
    base_url: String,
    _task: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
struct TestFixture {
    password: String,
    access_token: String,
    work_list_id: Uuid,
    task_id: Uuid,
    comment_id: Uuid,
    membership_id: Uuid,
    owner_user_id: Uuid,
    workspace_id: Uuid,
    mentioned_user_id: Uuid,
    list_key: SymmetricKey,
    binding_key: SymmetricKey,
    data_key_ciphertext: String,
    work_list_key_ciphertext: String,
    work_list_payload_ciphertext: String,
    task_title_ciphertext: String,
    task_payload_ciphertext: String,
    comment_body_ciphertext: String,
}

struct TestState {
    fixture: TestFixture,
    created_task_body: Option<TaskPayloadBody>,
    updated_task_body: Option<TaskPayloadBody>,
    created_comment_body: Option<CommentPayloadBody>,
    updated_comment_body: Option<CommentPayloadBody>,
}

impl TestState {
    fn new(fixture: TestFixture) -> Self {
        Self {
            fixture,
            created_task_body: None,
            updated_task_body: None,
            created_comment_body: None,
            updated_comment_body: None,
        }
    }
}

impl TestFixture {
    fn new() -> Self {
        let password = "correct horse battery staple".to_string();
        let data_key = SymmetricKey::new([0x11; 32]);
        let list_key = SymmetricKey::new([0x22; 32]);
        let binding_key = derive_payload_binding_key(&list_key).expect("binding key");
        let salt = [0x33; 32];

        let work_list_id = Uuid::now_v7();
        let task_id = Uuid::now_v7();
        let comment_id = Uuid::now_v7();
        let membership_id = Uuid::now_v7();
        let owner_user_id = Uuid::now_v7();
        let workspace_id = Uuid::now_v7();
        let mentioned_user_id = Uuid::now_v7();

        let data_key_ciphertext =
            encode_data_key_ciphertext(&password, &salt, &data_key).expect("data key ciphertext");
        let work_list_key_ciphertext =
            encode_membership_key_ciphertext(&data_key, &list_key).expect("membership key");
        let work_list_payload_ciphertext =
            encode_work_list_payload_ciphertext(&list_key).expect("work list payload");

        let existing_task_body = TaskPayloadBody {
            title: "Existing task".to_string(),
            rich_text: plaintext_rich_text("Existing task body"),
            checklist: Some(vec![worklist_client_crypto::ChecklistItemPayload {
                id: Uuid::now_v7().to_string(),
                title: "Keep checklist".to_string(),
                is_done: false,
                completed_at: None,
                assignee_user_ids: Some(vec![mentioned_user_id.to_string()]),
            }]),
            attachments: Some(vec![json!({"id": "attachment-1"})]),
            references: Some(vec![json!({"label": "ref", "uri": "https://example.test"})]),
            mentions: Some(vec![mentioned_user_id.to_string()]),
            client_meta: Some(json!({"source": "fixture"})),
            recurrence_state: Some(json!({"template_id": Uuid::now_v7().to_string()})),
        };
        let task_payload_ciphertext = encrypt_task_payload(
            &build_task_payload_envelope(existing_task_body.clone(), 1),
            &list_key,
        )
        .expect("task payload")
        .base64;
        let task_title_ciphertext = seal_text_value("Existing task").expect("task title").base64;

        let existing_comment_body = CommentPayloadBody {
            content: plaintext_rich_text("Existing comment").expect("comment rich text"),
            mentions: Some(vec![mentioned_user_id.to_string()]),
            attachments: Some(vec![json!({"kind": "file", "id": "comment-attachment"})]),
            client_meta: Some(json!({"source": "fixture"})),
        };
        let comment_body_ciphertext = encrypt_comment_payload(
            &build_comment_payload_envelope(existing_comment_body.clone(), 1),
            &list_key,
        )
        .expect("comment payload")
        .base64;

        Self {
            password,
            access_token: "test-access-token".to_string(),
            work_list_id,
            task_id,
            comment_id,
            membership_id,
            owner_user_id,
            workspace_id,
            mentioned_user_id,
            list_key,
            binding_key,
            data_key_ciphertext,
            work_list_key_ciphertext,
            work_list_payload_ciphertext,
            task_title_ciphertext,
            task_payload_ciphertext,
            comment_body_ciphertext,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTaskRequestBody {
    title_ciphertext: String,
    title_ciphertext_proof: String,
    payload_ciphertext: String,
    payload_ciphertext_proof: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateTaskRequestBody {
    title_ciphertext: Option<String>,
    title_ciphertext_proof: Option<String>,
    payload_ciphertext: Option<String>,
    payload_ciphertext_proof: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateCommentRequestBody {
    body_ciphertext: String,
    body_ciphertext_proof: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateCommentRequestBody {
    body_ciphertext: Option<String>,
    body_ciphertext_proof: Option<String>,
}

#[derive(Deserialize)]
struct IncludeArchivedQuery {
    #[serde(rename = "includeArchived")]
    include_archived: Option<bool>,
}

async fn spawn_server(state: Arc<Mutex<TestState>>) -> TestServer {
    let app = Router::new()
        .route("/work-lists/{id}", get(get_work_list))
        .route("/work-lists/{id}/tasks", get(list_tasks).post(create_task))
        .route(
            "/work-lists/{id}/tasks/{task_id}",
            get(get_task).patch(update_task),
        )
        .route(
            "/work-lists/{id}/tasks/{task_id}/comments",
            post(create_comment),
        )
        .route(
            "/work-lists/{id}/tasks/{task_id}/comments/{comment_id}",
            patch(update_comment),
        )
        .route("/me/tasks", get(list_my_tasks))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve app");
    });

    TestServer {
        base_url: format!("http://{}", addr),
        _task: task,
    }
}

async fn get_work_list(
    Path(work_list_id): Path<Uuid>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    authorize(&state, &headers);
    let state = state.lock().expect("state lock");
    assert_eq!(work_list_id, state.fixture.work_list_id);

    let payload = json!({
        "id": state.fixture.work_list_id,
        "ownerUserId": state.fixture.owner_user_id,
        "workspaceId": state.fixture.workspace_id,
        "titleCiphertext": seal_text_value("Fixture Work List").expect("title").base64,
        "descriptionCiphertext": null,
        "payloadCiphertext": state.fixture.work_list_payload_ciphertext,
        "timezone": "UTC",
        "sectionSnapshots": [],
        "createdAt": Utc::now(),
        "updatedAt": Utc::now(),
        "membership": {
            "id": state.fixture.membership_id,
            "userId": state.fixture.owner_user_id,
            "userEmail": "fixture@example.test",
            "userName": "Fixture",
            "userAvatarColor": "#111111",
            "role": "owner",
            "status": "active",
            "workListKeyCiphertext": state.fixture.work_list_key_ciphertext,
            "recipientCiphertext": null,
            "invitePackageCiphertext": null,
            "saltMember": null,
            "expiresAt": null,
            "joinedAt": Utc::now(),
            "payloadBindingKey": null
        },
        "members": [
            {
                "id": state.fixture.membership_id,
                "userId": state.fixture.owner_user_id,
                "userEmail": "fixture@example.test",
                "userName": "Fixture",
                "userAvatarColor": "#111111",
                "role": "owner",
                "status": "active",
                "workListKeyCiphertext": state.fixture.work_list_key_ciphertext,
                "recipientCiphertext": null,
                "invitePackageCiphertext": null,
                "saltMember": null,
                "expiresAt": null,
                "joinedAt": Utc::now(),
                "payloadBindingKey": null
            }
        ]
    });

    (StatusCode::OK, Json(payload))
}

async fn list_tasks(
    Path(work_list_id): Path<Uuid>,
    Query(query): Query<IncludeArchivedQuery>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    authorize(&state, &headers);
    let _ = query.include_archived;
    let state = state.lock().expect("state lock");
    assert_eq!(work_list_id, state.fixture.work_list_id);

    let payload = json!({
        "tasks": [task_response_json(&state)],
        "archivedCounts": [
            {
                "sectionId": null,
                "count": 0
            }
        ]
    });

    (StatusCode::OK, Json(payload))
}

async fn list_my_tasks(
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    authorize(&state, &headers);
    let state = state.lock().expect("state lock");

    let payload = json!({
        "tasks": [
            {
                "id": state.fixture.task_id,
                "workListId": state.fixture.work_list_id,
                "workListTitleCiphertext": seal_text_value("Fixture Work List").expect("title").base64,
                "createdByMembershipId": state.fixture.membership_id,
                "titleCiphertext": state.fixture.task_title_ciphertext,
                "payloadCiphertext": state.fixture.task_payload_ciphertext,
                "sectionId": null,
                "priority": null,
                "dueAt": null,
                "startAt": null,
                "completedAt": null,
                "isCompleted": false,
                "createdAt": Utc::now(),
                "updatedAt": Utc::now(),
                "commentCount": 1,
                "delegations": [
                    {
                        "id": Uuid::now_v7(),
                        "taskId": state.fixture.task_id,
                        "membershipId": state.fixture.membership_id,
                        "role": "assigned",
                        "status": "pending",
                        "noteCiphertext": null,
                        "createdAt": Utc::now(),
                        "updatedAt": Utc::now()
                    }
                ]
            }
        ],
        "total": 1,
        "limit": 100,
        "offset": 0
    });

    (StatusCode::OK, Json(payload))
}

async fn get_task(
    Path((work_list_id, task_id)): Path<(Uuid, Uuid)>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    authorize(&state, &headers);
    let state = state.lock().expect("state lock");
    assert_eq!(work_list_id, state.fixture.work_list_id);
    assert_eq!(task_id, state.fixture.task_id);

    let payload = json!({
        "id": state.fixture.task_id,
        "workListId": state.fixture.work_list_id,
        "createdByMembershipId": state.fixture.membership_id,
        "titleCiphertext": state.fixture.task_title_ciphertext,
        "payloadCiphertext": state.fixture.task_payload_ciphertext,
        "sectionId": null,
        "priority": null,
        "position": "a",
        "dueAt": null,
        "startAt": null,
        "completedAt": null,
        "archivedAt": null,
        "isCompleted": false,
        "recurrenceId": null,
        "recurrenceSchedule": null,
        "recurrenceIteration": null,
        "materializedAt": null,
        "createdAt": Utc::now(),
        "updatedAt": Utc::now(),
        "commentCount": 1,
        "delegations": [],
        "comments": [
            {
                "id": state.fixture.comment_id,
                "taskId": state.fixture.task_id,
                "authorMembershipId": state.fixture.membership_id,
                "bodyCiphertext": state.fixture.comment_body_ciphertext,
                "createdAt": Utc::now(),
                "updatedAt": Utc::now()
            }
        ]
    });

    (StatusCode::OK, Json(payload))
}

async fn create_task(
    Path(work_list_id): Path<Uuid>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
    Json(payload): Json<CreateTaskRequestBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    authorize(&state, &headers);
    let mut state = state.lock().expect("state lock");
    assert_eq!(work_list_id, state.fixture.work_list_id);

    let title_bytes = decode_b64(&payload.title_ciphertext);
    let title_proof =
        compute_payload_proof(&title_bytes, &state.fixture.binding_key).expect("title proof");
    assert_eq!(title_proof, payload.title_ciphertext_proof);

    let payload_bytes = decode_b64(&payload.payload_ciphertext);
    let payload_proof =
        compute_payload_proof(&payload_bytes, &state.fixture.binding_key).expect("payload proof");
    assert_eq!(payload_proof, payload.payload_ciphertext_proof);

    let decrypted = decrypt_task_payload(&state.fixture.list_key, &payload_bytes)
        .expect("decrypt created task");
    state.created_task_body = Some(decrypted.body.clone());

    let response = json!({
        "id": Uuid::now_v7(),
        "workListId": state.fixture.work_list_id,
        "createdByMembershipId": state.fixture.membership_id,
        "titleCiphertext": payload.title_ciphertext,
        "payloadCiphertext": payload.payload_ciphertext,
        "sectionId": null,
        "priority": null,
        "position": "b",
        "dueAt": null,
        "startAt": null,
        "completedAt": null,
        "archivedAt": null,
        "isCompleted": false,
        "recurrenceId": null,
        "recurrenceSchedule": null,
        "recurrenceIteration": null,
        "materializedAt": null,
        "createdAt": Utc::now(),
        "updatedAt": Utc::now(),
        "commentCount": 0,
        "delegations": []
    });

    (StatusCode::OK, Json(response))
}

async fn update_task(
    Path((work_list_id, task_id)): Path<(Uuid, Uuid)>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
    Json(payload): Json<UpdateTaskRequestBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    authorize(&state, &headers);
    let mut state = state.lock().expect("state lock");
    assert_eq!(work_list_id, state.fixture.work_list_id);
    assert_eq!(task_id, state.fixture.task_id);

    let payload_ciphertext = payload
        .payload_ciphertext
        .as_ref()
        .expect("payload ciphertext present");
    let payload_bytes = decode_b64(payload_ciphertext);
    let payload_proof =
        compute_payload_proof(&payload_bytes, &state.fixture.binding_key).expect("payload proof");
    assert_eq!(
        payload.payload_ciphertext_proof.as_deref(),
        Some(payload_proof.as_str())
    );

    if let Some(title_ciphertext) = payload.title_ciphertext.as_ref() {
        let title_bytes = decode_b64(title_ciphertext);
        let title_proof =
            compute_payload_proof(&title_bytes, &state.fixture.binding_key).expect("title proof");
        assert_eq!(
            payload.title_ciphertext_proof.as_deref(),
            Some(title_proof.as_str())
        );
    }

    let decrypted = decrypt_task_payload(&state.fixture.list_key, &payload_bytes)
        .expect("decrypt updated task");
    state.updated_task_body = Some(decrypted.body.clone());

    let response = json!({
        "id": state.fixture.task_id,
        "workListId": state.fixture.work_list_id,
        "createdByMembershipId": state.fixture.membership_id,
        "titleCiphertext": payload.title_ciphertext.unwrap_or_else(|| state.fixture.task_title_ciphertext.clone()),
        "payloadCiphertext": payload.payload_ciphertext.unwrap_or_else(|| state.fixture.task_payload_ciphertext.clone()),
        "sectionId": null,
        "priority": null,
        "position": "a",
        "dueAt": null,
        "startAt": null,
        "completedAt": null,
        "archivedAt": null,
        "isCompleted": false,
        "recurrenceId": null,
        "recurrenceSchedule": null,
        "recurrenceIteration": null,
        "materializedAt": null,
        "createdAt": Utc::now(),
        "updatedAt": Utc::now(),
        "commentCount": 1,
        "delegations": []
    });

    (StatusCode::OK, Json(response))
}

async fn create_comment(
    Path((work_list_id, task_id)): Path<(Uuid, Uuid)>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
    Json(payload): Json<CreateCommentRequestBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    authorize(&state, &headers);
    let mut state = state.lock().expect("state lock");
    assert_eq!(work_list_id, state.fixture.work_list_id);
    assert_eq!(task_id, state.fixture.task_id);

    let body_bytes = decode_b64(&payload.body_ciphertext);
    let body_proof =
        compute_payload_proof(&body_bytes, &state.fixture.binding_key).expect("comment proof");
    assert_eq!(body_proof, payload.body_ciphertext_proof);

    let decrypted = decrypt_comment_payload(&state.fixture.list_key, &body_bytes)
        .expect("decrypt created comment");
    state.created_comment_body = Some(decrypted.body.clone());

    let response = json!({
        "id": Uuid::now_v7(),
        "taskId": state.fixture.task_id,
        "authorMembershipId": state.fixture.membership_id,
        "bodyCiphertext": payload.body_ciphertext,
        "createdAt": Utc::now(),
        "updatedAt": Utc::now()
    });

    (StatusCode::CREATED, Json(response))
}

async fn update_comment(
    Path((work_list_id, task_id, comment_id)): Path<(Uuid, Uuid, Uuid)>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
    Json(payload): Json<UpdateCommentRequestBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    authorize(&state, &headers);
    let mut state = state.lock().expect("state lock");
    assert_eq!(work_list_id, state.fixture.work_list_id);
    assert_eq!(task_id, state.fixture.task_id);
    assert_eq!(comment_id, state.fixture.comment_id);

    let body_ciphertext = payload
        .body_ciphertext
        .as_ref()
        .expect("body ciphertext present");
    let body_bytes = decode_b64(body_ciphertext);
    let body_proof =
        compute_payload_proof(&body_bytes, &state.fixture.binding_key).expect("comment proof");
    assert_eq!(
        payload.body_ciphertext_proof.as_deref(),
        Some(body_proof.as_str())
    );

    let decrypted = decrypt_comment_payload(&state.fixture.list_key, &body_bytes)
        .expect("decrypt updated comment");
    state.updated_comment_body = Some(decrypted.body.clone());

    let response = json!({
        "id": state.fixture.comment_id,
        "taskId": state.fixture.task_id,
        "authorMembershipId": state.fixture.membership_id,
        "bodyCiphertext": body_ciphertext,
        "createdAt": Utc::now(),
        "updatedAt": Utc::now()
    });

    (StatusCode::OK, Json(response))
}

fn run_cli(home: &std::path::Path, api_url: &str, args: &[&str], stdin: Option<&str>) -> CliOutput {
    let mut command = Command::cargo_bin("worklist-cli-oss").expect("binary");
    command.env("HOME", home);
    command.arg("--api-url").arg(api_url);
    command.args(args);
    if let Some(stdin) = stdin {
        command.write_stdin(stdin.to_string());
    }

    let output = command.output().expect("run cli");
    CliOutput {
        status: output.status,
        stdout: String::from_utf8(output.stdout).expect("stdout utf8"),
        stderr: String::from_utf8(output.stderr).expect("stderr utf8"),
    }
}

fn seed_credentials(home: &std::path::Path, fixture: &TestFixture, api_url: &str) {
    let credentials = Credentials {
        api_url: api_url.to_string(),
        access_token: fixture.access_token.clone(),
        refresh_token: "refresh-token".to_string(),
        access_expires_at: Utc::now() + Duration::hours(1),
        refresh_expires_at: Utc::now() + Duration::days(1),
        user_id: fixture.owner_user_id,
        email: "fixture@example.test".to_string(),
        data_key_ciphertext: fixture.data_key_ciphertext.clone(),
    };

    let config_dir = home.join(".worklist");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    let path = config_dir.join("credentials.json");
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&credentials).expect("serialize creds"),
    )
    .expect("write creds");
}

fn authorize(state: &Arc<Mutex<TestState>>, headers: &HeaderMap) {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .expect("authorization header");
    let expected = {
        let state = state.lock().expect("state lock");
        format!("Bearer {}", state.fixture.access_token)
    };
    assert_eq!(token, expected);
}

fn decode_b64(value: &str) -> Vec<u8> {
    STANDARD_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
        .expect("decode base64")
}

fn encode_data_key_ciphertext(
    password: &str,
    salt: &[u8; 32],
    data_key: &SymmetricKey,
) -> worklist_client_core::PublicResult<String> {
    let wrapping_key = worklist_client_crypto::KeyDerivationService::new()
        .derive_master_key(password.as_bytes(), salt)?;
    let strong_box = StrongBoxKeyRing::new(wrapping_key).strong_box();
    let sealed = strong_box
        .encrypt(data_key.as_bytes(), USER_DATA_KEY_CONTEXT)
        .expect("seal data key");
    let payload = SealedPayload::new([salt.as_slice(), sealed.as_slice()].concat()).to_bytes()?;
    Ok(STANDARD_NO_PAD.encode(payload))
}

fn encode_membership_key_ciphertext(
    data_key: &SymmetricKey,
    list_key: &SymmetricKey,
) -> worklist_client_core::PublicResult<String> {
    let strong_box = StrongBoxKeyRing::new(data_key.clone()).strong_box();
    let sealed = strong_box
        .encrypt(list_key.as_bytes(), WORK_LIST_MEMBERSHIP_CONTEXT)
        .expect("seal membership key");
    let payload = SealedPayload::new(sealed).to_bytes()?;
    Ok(STANDARD_NO_PAD.encode(payload))
}

fn encode_work_list_payload_ciphertext(
    list_key: &SymmetricKey,
) -> worklist_client_core::PublicResult<String> {
    let plaintext = serialize_to_cbor(&json!({
        "kind": "work_list",
        "version": 1,
        "body": {
            "title": "Fixture Work List",
            "description": null,
            "sections": [],
            "client_meta": {
                "web.view": {
                    "layout": "kanban"
                }
            }
        }
    }))?;
    let strong_box = StrongBoxKeyRing::new(list_key.clone()).strong_box();
    let sealed = strong_box
        .encrypt(plaintext, WORK_LIST_PAYLOAD_CONTEXT)
        .expect("seal work list payload");
    let payload = SealedPayload::new(sealed).to_bytes()?;
    Ok(STANDARD_NO_PAD.encode(payload))
}

fn task_response_json(state: &TestState) -> serde_json::Value {
    json!({
        "id": state.fixture.task_id,
        "workListId": state.fixture.work_list_id,
        "createdByMembershipId": state.fixture.membership_id,
        "titleCiphertext": state.fixture.task_title_ciphertext,
        "payloadCiphertext": state.fixture.task_payload_ciphertext,
        "sectionId": null,
        "priority": null,
        "position": "a",
        "dueAt": null,
        "startAt": null,
        "completedAt": null,
        "archivedAt": null,
        "isCompleted": false,
        "recurrenceId": null,
        "recurrenceSchedule": null,
        "recurrenceIteration": null,
        "materializedAt": null,
        "createdAt": Utc::now(),
        "updatedAt": Utc::now(),
        "commentCount": 1,
        "delegations": [
            {
                "id": Uuid::now_v7(),
                "taskId": state.fixture.task_id,
                "membershipId": state.fixture.membership_id,
                "role": "assigned",
                "status": "pending",
                "noteCiphertext": null,
                "createdAt": Utc::now(),
                "updatedAt": Utc::now()
            }
        ]
    })
}

struct CliOutput {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

fn write_json_file(dir: &FsPath, name: &str, value: &serde_json::Value) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(value).expect("serialize json"),
    )
    .expect("write json file");
    path
}
