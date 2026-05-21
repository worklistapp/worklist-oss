use std::io::{Read, Write};
use std::path::Path as FsPath;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use assert_cmd::Command;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, patch, post},
};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use strong_box::StrongBox;
use tempfile::TempDir;
use tokio::net::TcpListener;
use uuid::Uuid;
use worklist_client_api::{AuditPatchFieldRequest, AuditPatchRequest};
use worklist_client_auth::{
    AgentCredentials, Credentials, agent_key_material_from_seed, normalize_api_url,
};
use worklist_client_crypto::{
    ATTACHMENT_BLOB_CONTEXT, ATTACHMENT_BLOB_CONTEXT_LABEL, ATTACHMENT_BLOB_REF_VERSION,
    ATTACHMENT_REF_CONTEXT, AttachmentBlobRef, CommentPayloadBody, FlexibleValue, SealedPayload,
    StrongBoxKeyRing, SymmetricKey, TaskPayloadBody, USER_DATA_KEY_CONTEXT,
    WORK_LIST_MEMBERSHIP_CONTEXT, WORK_LIST_PAYLOAD_CONTEXT, build_comment_payload_envelope,
    build_task_payload_envelope, compute_payload_proof, decrypt_comment_payload,
    decrypt_task_payload, decrypt_task_title_for_id, derive_payload_binding_key,
    encrypt_agent_work_list_key, encrypt_comment_payload, encrypt_task_payload,
    flexible_value_to_json, json_value_to_flexible, plaintext_rich_text, seal_task_title,
    seal_work_list_title, serialize_to_cbor,
};

const AUTHORIZED_USER_TOKEN_LABEL: &str = "user";
const AUTHORIZED_AGENT_TOKEN_LABEL: &str = "agent";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_proven_flows_round_trip_through_mock_api() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state.clone()).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let list_detail_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "lists",
            "get",
            &fixture.work_list_id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        list_detail_output.status.success(),
        "lists get failed: {}",
        list_detail_output.stderr
    );
    let list_detail: Value = parse_stdout_json(&list_detail_output.stdout);
    assert_eq!(list_detail["title"], "Fixture Work List");
    assert!(list_detail.get("titleCiphertext").is_none());

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
    let created_task_json: Value = parse_stdout_json(&create_task_output.stdout);
    assert_eq!(created_task_json["title"], "Created from test");
    assert!(created_task_json.get("titleCiphertext").is_none());

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
    let updated_task_json: Value = parse_stdout_json(&update_task_output.stdout);
    assert_eq!(updated_task_json["title"], "Updated title");
    assert_eq!(updated_task_json["bodyMarkdown"], "Updated body");

    let move_section_id = Uuid::now_v7();
    let insert_before_task_id = Uuid::now_v7();
    let move_task_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "tasks",
            "move",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--section-id",
            &move_section_id.to_string(),
            "--insert-before-task-id",
            &insert_before_task_id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        move_task_output.status.success(),
        "task move failed: {}",
        move_task_output.stderr
    );
    let moved_task_json: Value = parse_stdout_json(&move_task_output.stdout);
    assert_eq!(moved_task_json["sectionId"], move_section_id.to_string());

    let archive_task_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "tasks",
            "archive",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        archive_task_output.status.success(),
        "task archive failed: {}",
        archive_task_output.stderr
    );
    let archived_task_json: Value = parse_stdout_json(&archive_task_output.stdout);
    assert!(archived_task_json["archivedAt"].is_string());

    let unarchive_task_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "tasks",
            "unarchive",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        unarchive_task_output.status.success(),
        "task unarchive failed: {}",
        unarchive_task_output.stderr
    );
    let unarchived_task_json: Value = parse_stdout_json(&unarchive_task_output.stdout);
    assert!(unarchived_task_json["archivedAt"].is_null());

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
    let created_comment_json: Value = parse_stdout_json(&create_comment_output.stdout);
    assert_eq!(created_comment_json["bodyMarkdown"], "New comment");

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
    let updated_comment_json: Value = parse_stdout_json(&update_comment_output.stdout);
    assert_eq!(updated_comment_json["bodyMarkdown"], "Updated comment");

    let list_comments_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "comments",
            "list",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        list_comments_output.status.success(),
        "comment list failed: {}",
        list_comments_output.stderr
    );
    let list_comments_json: Value = parse_stdout_json(&list_comments_output.stdout);
    assert_eq!(list_comments_json[0]["bodyMarkdown"], "Existing comment");

    let (delete_comment_input, expected_delete_comment_audit_patch) = delete_input(
        "bodyCiphertextDigest",
        "comment-delete-ciphertext",
        "comment-delete-proof",
    );
    let delete_comment_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "comments",
            "delete",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--comment-id",
            &fixture.comment_id.to_string(),
            "--input-stdin",
        ],
        Some(&delete_comment_input.to_string()),
    );
    assert!(
        delete_comment_output.status.success(),
        "comment delete failed: {}",
        delete_comment_output.stderr
    );
    let deleted_comment_json: Value = parse_stdout_json(&delete_comment_output.stdout);
    assert_eq!(deleted_comment_json["deleted"], true);
    assert_eq!(
        deleted_comment_json["commentId"],
        fixture.comment_id.to_string()
    );

    let empty_comments_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "comments",
            "list",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        empty_comments_output.status.success(),
        "empty comment list failed: {}",
        empty_comments_output.stderr
    );
    let empty_comments_json: Value = parse_stdout_json(&empty_comments_output.stdout);
    assert_eq!(empty_comments_json, json!([]));

    let (delete_task_input, expected_delete_task_audit_patch) = delete_input(
        "payloadCiphertextDigest",
        "task-delete-ciphertext",
        "task-delete-proof",
    );
    let delete_task_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "tasks",
            "delete",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--input-stdin",
        ],
        Some(&delete_task_input.to_string()),
    );
    assert!(
        delete_task_output.status.success(),
        "task delete failed: {}",
        delete_task_output.stderr
    );
    let deleted_task_json: Value = parse_stdout_json(&delete_task_output.stdout);
    assert_eq!(deleted_task_json["deleted"], true);
    assert_eq!(deleted_task_json["taskId"], fixture.task_id.to_string());

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
        4
    );
    assert_eq!(
        updated_task.mentions.as_ref().expect("mentions preserved")[0],
        fixture.mentioned_user_id.to_string()
    );
    let moved_task = state
        .moved_task_body
        .as_ref()
        .expect("moved task request recorded");
    assert_eq!(moved_task.section_id, Some(move_section_id));
    assert_eq!(
        moved_task.insert_before_task_id,
        Some(insert_before_task_id)
    );
    assert_eq!(state.archive_task_count, 1);
    assert_eq!(state.unarchive_task_count, 1);

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
        flexible_value_to_json(
            updated_comment
                .client_meta
                .as_ref()
                .expect("comment client meta preserved")
                .clone(),
        )["source"],
        "fixture"
    );
    assert_eq!(state.list_comments_count, 2);
    assert_eq!(state.deleted_comment_id, Some(fixture.comment_id));
    assert_eq!(state.deleted_task_id, Some(fixture.task_id));
    assert_eq!(
        state.deleted_comment_audit_patch.as_ref(),
        Some(&expected_delete_comment_audit_patch)
    );
    assert_eq!(
        state.deleted_task_audit_patch.as_ref(),
        Some(&expected_delete_task_audit_patch)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_task_reads_parse_current_api_shapes() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let lists_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "lists", "--password-stdin"],
        Some(&fixture.password),
    );
    assert!(
        lists_output.status.success(),
        "lists failed: {}",
        lists_output.stderr
    );
    let lists_json: Value = parse_stdout_json(&lists_output.stdout);
    assert_eq!(lists_json[0]["title"], "Fixture Work List");
    assert!(lists_json[0].get("payloadCiphertext").is_none());

    let list_detail_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "lists",
            "get",
            &fixture.work_list_id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        list_detail_output.status.success(),
        "lists get failed: {}",
        list_detail_output.stderr
    );
    let list_detail_json: Value = parse_stdout_json(&list_detail_output.stdout);
    assert_eq!(list_detail_json["title"], "Fixture Work List");
    assert_eq!(list_detail_json["members"][0]["role"], "owner");

    let my_tasks_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "tasks", "list", "--all", "--password-stdin"],
        Some(&fixture.password),
    );
    assert!(
        my_tasks_output.status.success(),
        "my tasks failed: {}",
        my_tasks_output.stderr
    );
    let my_tasks_json: Value = parse_stdout_json(&my_tasks_output.stdout);
    assert_eq!(my_tasks_json[0]["id"], fixture.task_id.to_string());
    assert_eq!(my_tasks_json[0]["title"], "Existing task");
    assert_eq!(my_tasks_json[0]["bodyMarkdown"], "Existing task body");
    assert_eq!(my_tasks_json[0]["workListTitle"], "Fixture Work List");
    assert!(my_tasks_json[0].get("titleCiphertext").is_none());
    assert!(my_tasks_json[0].get("payloadCiphertext").is_none());

    let list_tasks_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "tasks",
            "list",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        list_tasks_output.status.success(),
        "list tasks failed: {}",
        list_tasks_output.stderr
    );
    let list_tasks_json: Value = parse_stdout_json(&list_tasks_output.stdout);
    assert_eq!(list_tasks_json[0]["title"], "Existing task");
    assert_eq!(list_tasks_json[0]["bodyMarkdown"], "Existing task body");

    let task_detail_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "tasks",
            "get",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        task_detail_output.status.success(),
        "task get failed: {}",
        task_detail_output.stderr
    );
    let task_detail_json: Value = parse_stdout_json(&task_detail_output.stdout);
    assert_eq!(task_detail_json["title"], "Existing task");
    assert_eq!(
        task_detail_json["comments"][0]["bodyMarkdown"],
        "Existing comment"
    );
    assert_eq!(task_detail_json["clientMeta"]["source"], "fixture");
    assert_eq!(task_detail_json["clientMeta"]["blob"], json!([1, 2, 3, 4]));
    assert_eq!(
        task_detail_json["attachments"][0]["id"],
        fixture.text_attachment.id.to_string()
    );
    assert_eq!(task_detail_json["attachments"][0]["fileName"], "notes.md");
    assert_eq!(
        task_detail_json["attachments"][0]["contentType"],
        "text/markdown"
    );
    assert!(task_detail_json["attachments"][0].get("blobKey").is_none());
    assert_eq!(
        task_detail_json["comments"][0]["clientMeta"]["blob"],
        json!([9, 8, 7])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_rejects_plaintext_scalar_delete_audit_patch_before_request() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state.clone()).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);
    let plaintext_delete_input = json!({
        "auditPatch": {
            "fields": [
                {
                    "field": "CLIENT-ENC field sentinel",
                    "changeKind": "clear",
                    "beforeScalar": "CLIENT-ENC sentinel plaintext"
                }
            ],
            "payloadCiphertext": "ciphertext",
            "payloadCiphertextProof": "proof",
            "payloadVersion": 1
        }
    });

    let delete_task_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "tasks",
            "delete",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--input-stdin",
        ],
        Some(&plaintext_delete_input.to_string()),
    );

    assert!(!delete_task_output.status.success());
    assert!(delete_task_output.stdout.is_empty());
    assert_json_error_contains(&delete_task_output.stderr, "plaintext scalar values");
    assert!(
        !delete_task_output
            .stderr
            .contains("CLIENT-ENC field sentinel")
    );
    assert!(
        !delete_task_output
            .stderr
            .contains("CLIENT-ENC sentinel plaintext")
    );

    let delete_comment_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "comments",
            "delete",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--comment-id",
            &fixture.comment_id.to_string(),
            "--input-stdin",
        ],
        Some(&plaintext_delete_input.to_string()),
    );

    assert!(!delete_comment_output.status.success());
    assert!(delete_comment_output.stdout.is_empty());
    assert_json_error_contains(&delete_comment_output.stderr, "plaintext scalar values");
    assert!(
        !delete_comment_output
            .stderr
            .contains("CLIENT-ENC field sentinel")
    );
    assert!(
        !delete_comment_output
            .stderr
            .contains("CLIENT-ENC sentinel plaintext")
    );

    let state = state.lock().expect("state lock");
    assert!(state.deleted_task_id.is_none());
    assert!(state.deleted_comment_id.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_persists_rotated_refresh_tokens_after_automatic_refresh() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state.clone()).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials_with_expiry(
        home.path(),
        &fixture,
        &server.base_url,
        Utc::now() - Duration::minutes(5),
        Utc::now() + Duration::days(1),
    );

    let first_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "tasks",
            "get",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        first_output.status.success(),
        "first task get failed: {}",
        first_output.stderr
    );

    let credentials_path = home.path().join(".worklist").join("credentials.json");
    let mut saved_credentials: Credentials = serde_json::from_slice(
        &std::fs::read(&credentials_path).expect("read credentials after first task get"),
    )
    .expect("parse credentials after first task get");
    saved_credentials.access_expires_at = Utc::now() - Duration::minutes(5);
    std::fs::write(
        &credentials_path,
        serde_json::to_vec_pretty(&saved_credentials).expect("serialize expired credentials"),
    )
    .expect("rewrite credentials");

    let second_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "tasks",
            "get",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        second_output.status.success(),
        "second task get failed: {}",
        second_output.stderr
    );

    let saved_credentials: Credentials =
        serde_json::from_slice(&std::fs::read(&credentials_path).expect("read credentials"))
            .expect("parse credentials");

    let state = state.lock().expect("state lock");
    assert_eq!(state.refresh_request_count, 2);
    assert_eq!(saved_credentials.refresh_token, state.current_refresh_token);
    assert_eq!(saved_credentials.access_token, state.current_access_token);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_inspect_returns_decrypted_work_list_detail() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let inspect_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
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
    let inspect_json: Value = parse_stdout_json(&inspect_output.stdout);
    assert_eq!(inspect_json["title"], "Fixture Work List");
    assert_eq!(
        inspect_json["payload"]["body"]["title"],
        "Fixture Work List"
    );
    assert!(inspect_json.get("payloadCiphertext").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_reads_surface_partial_decryption_errors() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    {
        let mut guard = state.lock().expect("state lock");
        guard.invalid_work_list_payload = true;
        guard.invalid_task_payload = true;
    }
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let lists_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "lists", "--password-stdin"],
        Some(&fixture.password),
    );
    assert!(
        lists_output.status.success(),
        "lists failed: {}",
        lists_output.stderr
    );
    let lists_json: Value = parse_stdout_json(&lists_output.stdout);
    assert_eq!(lists_json[0]["title"], "Fixture Work List");
    assert_eq!(lists_json[0]["readError"]["code"], "work_list_payload");

    let tasks_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "tasks", "list", "--all", "--password-stdin"],
        Some(&fixture.password),
    );
    assert!(
        tasks_output.status.success(),
        "tasks failed: {}",
        tasks_output.stderr
    );
    let tasks_json: Value = parse_stdout_json(&tasks_output.stdout);
    assert_eq!(tasks_json[0]["title"], "Existing task");
    assert_eq!(tasks_json[0]["readError"]["code"], "task_payload");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_tasks_do_not_inherit_work_list_payload_errors_when_task_decrypts() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    {
        let mut guard = state.lock().expect("state lock");
        guard.invalid_work_list_payload = true;
    }
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let tasks_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "tasks", "list", "--all", "--password-stdin"],
        Some(&fixture.password),
    );
    assert!(
        tasks_output.status.success(),
        "tasks failed: {}",
        tasks_output.stderr
    );
    let tasks_json: Value = parse_stdout_json(&tasks_output.stdout);
    assert_eq!(tasks_json[0]["title"], "Existing task");
    assert!(tasks_json[0].get("readError").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_reads_surface_attachment_projection_errors() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    {
        let mut guard = state.lock().expect("state lock");
        guard.invalid_task_attachment_metadata = true;
        guard.invalid_comment_attachment_metadata = true;
    }
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "tasks",
            "get",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );

    assert!(
        output.status.success(),
        "task get failed: {}",
        output.stderr
    );
    let task_json: Value = parse_stdout_json(&output.stdout);
    assert_eq!(task_json["title"], "Existing task");
    assert_eq!(task_json["bodyMarkdown"], "Existing task body");
    assert_eq!(task_json["readError"]["code"], "task_attachments");
    assert!(task_json["attachments"].is_null());
    assert_eq!(task_json["comments"][0]["bodyMarkdown"], "Existing comment");
    assert_eq!(
        task_json["comments"][0]["readError"]["code"],
        "comment_attachments"
    );
    assert!(task_json["comments"][0]["attachments"].is_null());
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
    assert!(output.stdout.contains("get"));
    assert!(output.stdout.contains("create"));
    assert!(output.stdout.contains("update"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_task_detail_table_lists_attachments() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "tasks",
            "get",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );

    assert!(
        output.status.success(),
        "task get failed: {}",
        output.stderr
    );
    assert!(output.stdout.contains("Attachments"));
    assert!(
        output
            .stdout
            .contains(&fixture.text_attachment.id.to_string())
    );
    assert!(output.stdout.contains("notes.md"));
    assert!(output.stdout.contains("spec.pdf"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_reads_text_attachment_to_stdout() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "tasks",
            "attachments",
            "read",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--attachment-id",
            &fixture.text_attachment.id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );

    assert!(
        output.status.success(),
        "attachment read failed: {}",
        output.stderr
    );
    assert_eq!(output.stdout, "# Heading\n\nAttachment body\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_attachment_read_exits_zero_when_stdout_pipe_closes() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let output = run_cli_with_closed_stdout(
        home.path(),
        &server.base_url,
        &[
            "tasks",
            "attachments",
            "read",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--attachment-id",
            &fixture.text_attachment.id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );

    assert!(
        output.status.success(),
        "attachment read with closed stdout failed: {}",
        output.stderr
    );
    assert_eq!(output.stderr, "");
    assert_eq!(output.stdout, "");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_reads_markdown_text_attachment_as_json() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "tasks",
            "attachments",
            "read",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--attachment-id",
            &fixture.text_attachment.id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );

    assert!(
        output.status.success(),
        "markdown text attachment json read failed: {}",
        output.stderr
    );
    let attachment_json = parse_stdout_json(&output.stdout);
    assert_eq!(
        attachment_json["attachment"]["id"],
        fixture.text_attachment.id.to_string()
    );
    assert_eq!(attachment_json["contentFormat"], "markdown");
    assert_eq!(attachment_json["sourceKind"], "plain_text");
    assert_eq!(attachment_json["text"], "# Heading\n\nAttachment body\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_reads_docx_attachment_to_markdown_stdout() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "tasks",
            "attachments",
            "read",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--attachment-id",
            &fixture.docx_attachment.id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );

    assert!(
        output.status.success(),
        "docx attachment read failed: {}",
        output.stderr
    );
    assert_eq!(output.stdout, "Heading\n\nDOCX body\n\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_reads_docx_attachment_as_json() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "tasks",
            "attachments",
            "read",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--attachment-id",
            &fixture.docx_attachment.id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );

    assert!(
        output.status.success(),
        "docx attachment json read failed: {}",
        output.stderr
    );
    let attachment_json = parse_stdout_json(&output.stdout);
    assert_eq!(
        attachment_json["attachment"]["id"],
        fixture.docx_attachment.id.to_string()
    );
    assert_eq!(attachment_json["attachment"]["fileName"], "spec.docx");
    assert_eq!(attachment_json["contentFormat"], "markdown");
    assert_eq!(attachment_json["sourceKind"], "docx_rendered");
    assert_eq!(attachment_json["text"], "Heading\n\nDOCX body\n\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_rejects_binary_attachment_reads() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state.clone()).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "tasks",
            "attachments",
            "read",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--attachment-id",
            &fixture.binary_attachment.id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );

    assert!(
        !output.status.success(),
        "binary attachment read unexpectedly succeeded"
    );
    assert!(output.stderr.contains("use download instead"));
    let state = state.lock().expect("state lock");
    assert_eq!(state.attachment_download_requests, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_downloads_binary_attachment_to_default_filename() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    let download_dir = TempDir::new().expect("download dir");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let output = run_cli_in_dir(
        home.path(),
        download_dir.path(),
        &server.base_url,
        &[
            "tasks",
            "attachments",
            "download",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--attachment-id",
            &fixture.binary_attachment.id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );

    assert!(
        output.status.success(),
        "attachment download failed: {}",
        output.stderr
    );
    let saved_path = download_dir.path().join("spec.pdf");
    assert_eq!(
        std::fs::read(&saved_path).expect("saved attachment"),
        fixture.binary_attachment.plaintext_bytes
    );
    assert!(output.stdout.contains("Saved attachment"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_download_respects_output_path_and_force() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    let download_dir = TempDir::new().expect("download dir");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let custom_path = download_dir.path().join("nested").join("custom.bin");
    std::fs::create_dir_all(custom_path.parent().expect("parent")).expect("create parent");
    std::fs::write(&custom_path, b"existing").expect("write existing");

    let first_output = run_cli_in_dir(
        home.path(),
        download_dir.path(),
        &server.base_url,
        &[
            "tasks",
            "attachments",
            "download",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--attachment-id",
            &fixture.binary_attachment.id.to_string(),
            "--output",
            custom_path.to_str().expect("utf8 path"),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );

    assert!(
        !first_output.status.success(),
        "download unexpectedly overwrote file"
    );
    assert!(first_output.stderr.contains("already exists"));

    let second_output = run_cli_in_dir(
        home.path(),
        download_dir.path(),
        &server.base_url,
        &[
            "--json",
            "tasks",
            "attachments",
            "download",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--attachment-id",
            &fixture.binary_attachment.id.to_string(),
            "--output",
            custom_path.to_str().expect("utf8 path"),
            "--force",
            "--password-stdin",
        ],
        Some(&fixture.password),
    );

    assert!(
        second_output.status.success(),
        "forced download failed: {}",
        second_output.stderr
    );
    assert_eq!(
        std::fs::read(&custom_path).expect("forced download"),
        fixture.binary_attachment.plaintext_bytes
    );
    let result_json: Value = parse_stdout_json(&second_output.stdout);
    assert_eq!(result_json["fileName"], "spec.pdf");
    assert_eq!(result_json["outputPath"], custom_path.display().to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_download_sanitizes_default_attachment_filename() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    let download_dir = TempDir::new().expect("download dir");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let output = run_cli_in_dir(
        home.path(),
        download_dir.path(),
        &server.base_url,
        &[
            "tasks",
            "attachments",
            "download",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--attachment-id",
            &fixture.hostile_attachment.id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );

    assert!(
        output.status.success(),
        "sanitized download failed: {}",
        output.stderr
    );
    let saved_path = download_dir.path().join("unsafe.txt");
    assert_eq!(
        std::fs::read(&saved_path).expect("sanitized attachment"),
        fixture.hostile_attachment.plaintext_bytes
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_attachment_download_rejects_size_mismatch() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    {
        let mut guard = state.lock().expect("state lock");
        guard.attachment_size_mismatch = true;
    }
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    let download_dir = TempDir::new().expect("download dir");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let output = run_cli_in_dir(
        home.path(),
        download_dir.path(),
        &server.base_url,
        &[
            "tasks",
            "attachments",
            "download",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--attachment-id",
            &fixture.binary_attachment.id.to_string(),
            "--password-stdin",
        ],
        Some(&fixture.password),
    );

    assert!(
        !output.status.success(),
        "size mismatch download unexpectedly succeeded"
    );
    assert!(output.stderr.contains("download size mismatch"));
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
async fn cli_agent_approve_rejects_code_stdin_with_password_stdin() {
    let home = TempDir::new().expect("temp home");
    let output = run_cli(
        home.path(),
        "https://worklist.app",
        &[
            "--json",
            "agent",
            "approve",
            "--code-stdin",
            "--handle",
            "agent",
            "--display-name",
            "Agent",
            "--password-stdin",
        ],
        Some("enrollment-code\npassword"),
    );

    assert!(!output.status.success(), "command unexpectedly succeeded");
    assert!(
        output.stdout.is_empty(),
        "unexpected stdout: {}",
        output.stdout
    );
    assert_json_error_contains(&output.stderr, "cannot be used with");
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

    let task_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "tasks",
            "get",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
        ],
        None,
    );
    assert!(
        task_output.status.success(),
        "task get without password flag failed: {}",
        task_output.stderr
    );
    let task_json: Value = parse_stdout_json(&task_output.stdout);
    assert_eq!(task_json["title"], "Existing task");

    let lock_output = run_cli(home.path(), &server.base_url, &["auth", "lock"], None);
    assert!(
        lock_output.status.success(),
        "lock failed: {}",
        lock_output.stderr
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_keychain_store_bootstraps_later_decrypt_without_password_flag() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    let keychain_dir = TempDir::new().expect("temp keychain");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let store_output = run_cli_with_test_keychain(
        home.path(),
        &server.base_url,
        keychain_dir.path(),
        &["--json", "auth", "keychain", "store", "--password-stdin"],
        Some(&fixture.password),
    );
    assert!(
        store_output.status.success(),
        "keychain store failed: {}",
        store_output.stderr
    );
    let store_json: Value = parse_stdout_json(&store_output.stdout);
    assert_eq!(store_json["persistedBootstrap"]["status"], "available");

    let initial_status = run_cli_with_test_keychain(
        home.path(),
        &server.base_url,
        keychain_dir.path(),
        &["--json", "auth", "status"],
        None,
    );
    assert!(
        initial_status.status.success(),
        "status failed: {}",
        initial_status.stderr
    );
    let initial_status_json: Value = parse_stdout_json(&initial_status.stdout);
    assert_eq!(initial_status_json["loggedIn"], true);
    assert_eq!(initial_status_json["unlockDaemon"]["active"], false);
    assert_eq!(
        initial_status_json["persistedBootstrap"]["status"],
        "available"
    );

    let task_output = run_cli_with_test_keychain(
        home.path(),
        &server.base_url,
        keychain_dir.path(),
        &[
            "--json",
            "tasks",
            "get",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
        ],
        None,
    );
    assert!(
        task_output.status.success(),
        "task get without password flag failed: {}",
        task_output.stderr
    );
    let task_json: Value = parse_stdout_json(&task_output.stdout);
    assert_eq!(task_json["title"], "Existing task");

    let seeded_status = run_cli_with_test_keychain(
        home.path(),
        &server.base_url,
        keychain_dir.path(),
        &["--json", "auth", "status"],
        None,
    );
    assert!(
        seeded_status.status.success(),
        "status after bootstrap failed: {}",
        seeded_status.stderr
    );
    let seeded_status_json: Value = parse_stdout_json(&seeded_status.stdout);
    assert_eq!(seeded_status_json["unlockDaemon"]["active"], true);
    assert_eq!(
        seeded_status_json["persistedBootstrap"]["status"],
        "available"
    );

    let _ = run_cli(home.path(), &server.base_url, &["auth", "lock"], None);
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
        &[
            "--json",
            "auth",
            "unlock",
            "--ttl-seconds",
            "300",
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        unlock_output.status.success(),
        "unlock failed: {}",
        unlock_output.stderr
    );
    let unlock_json: Value = parse_stdout_json(&unlock_output.stdout);
    assert_eq!(unlock_json["unlocked"], true);
    assert_eq!(unlock_json["ttlSeconds"], 300);

    let logout_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "auth", "logout"],
        None,
    );
    assert!(
        logout_output.status.success(),
        "logout failed: {}",
        logout_output.stderr
    );
    let logout_json: Value = parse_stdout_json(&logout_output.stdout);
    assert_eq!(logout_json["loggedOut"], true);

    let status_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "auth", "status"],
        None,
    );
    assert!(
        status_output.status.success(),
        "status failed: {}",
        status_output.stderr
    );
    let status_json: Value = parse_stdout_json(&status_output.stdout);
    assert_eq!(status_json["loggedIn"], false);
    assert_eq!(status_json["unlockDaemon"]["active"], false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_logout_clears_persisted_bootstrap() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    let keychain_dir = TempDir::new().expect("temp keychain");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let store_output = run_cli_with_test_keychain(
        home.path(),
        &server.base_url,
        keychain_dir.path(),
        &["auth", "keychain", "store", "--password-stdin"],
        Some(&fixture.password),
    );
    assert!(
        store_output.status.success(),
        "keychain store failed: {}",
        store_output.stderr
    );

    let logout_output = run_cli_with_test_keychain(
        home.path(),
        &server.base_url,
        keychain_dir.path(),
        &["auth", "logout"],
        None,
    );
    assert!(
        logout_output.status.success(),
        "logout failed: {}",
        logout_output.stderr
    );

    seed_credentials(home.path(), &fixture, &server.base_url);
    let task_output = run_cli_with_test_keychain(
        home.path(),
        &server.base_url,
        keychain_dir.path(),
        &[
            "--json",
            "tasks",
            "get",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
        ],
        None,
    );
    assert!(
        !task_output.status.success(),
        "task get unexpectedly succeeded after logout"
    );
    assert!(
        task_output
            .stderr
            .contains("No unlocked local session or persisted bootstrap secret is available")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_logout_clears_agent_credentials_and_seed_when_agent_is_only_session() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    let agent_credentials = seed_agent_credentials(home.path(), &fixture, &server.base_url);
    let agent_seed_path = seed_agent_file_backed_secret(home.path(), &agent_credentials);

    let logout_output = run_cli_with_agent_seed_file_backend(
        home.path(),
        &server.base_url,
        &["--json", "auth", "logout"],
        None,
    );
    assert!(
        logout_output.status.success(),
        "logout failed: {}",
        logout_output.stderr
    );

    let logout_json: Value = parse_stdout_json(&logout_output.stdout);
    assert_eq!(logout_json["loggedOut"], true);
    assert!(
        !agent_credentials_file(home.path()).exists(),
        "agent credentials file should be removed"
    );
    assert!(
        !agent_seed_path.exists(),
        "agent seed file should be removed"
    );

    let status_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "auth", "status"],
        None,
    );
    assert!(
        status_output.status.success(),
        "status failed: {}",
        status_output.stderr
    );
    let status_json: Value = parse_stdout_json(&status_output.stdout);
    assert_eq!(status_json["loggedIn"], false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_logout_with_user_principal_preserves_agent_credentials_and_seed() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);
    let agent_credentials = seed_agent_credentials(home.path(), &fixture, &server.base_url);
    let agent_seed_path = seed_agent_file_backed_secret(home.path(), &agent_credentials);

    let logout_output = run_cli_with_agent_seed_file_backend(
        home.path(),
        &server.base_url,
        &["--json", "--principal", "user", "auth", "logout"],
        None,
    );
    assert!(
        logout_output.status.success(),
        "logout failed: {}",
        logout_output.stderr
    );

    let logout_json: Value = parse_stdout_json(&logout_output.stdout);
    assert_eq!(logout_json["loggedOut"], true);
    assert!(
        !user_credentials_file(home.path()).exists(),
        "user credentials file should be removed"
    );
    assert!(
        agent_credentials_file(home.path()).exists(),
        "agent credentials file should remain"
    );
    assert!(agent_seed_path.exists(), "agent seed file should remain");

    let status_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "--principal", "agent", "auth", "status"],
        None,
    );
    assert!(
        status_output.status.success(),
        "agent status failed: {}",
        status_output.stderr
    );
    let status_json: Value = parse_stdout_json(&status_output.stdout);
    assert_eq!(status_json["principalType"], "agent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_logout_with_agent_principal_preserves_user_credentials() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);
    let agent_credentials = seed_agent_credentials(home.path(), &fixture, &server.base_url);
    let agent_seed_path = seed_agent_file_backed_secret(home.path(), &agent_credentials);

    let logout_output = run_cli_with_agent_seed_file_backend(
        home.path(),
        &server.base_url,
        &["--json", "--principal", "agent", "auth", "logout"],
        None,
    );
    assert!(
        logout_output.status.success(),
        "logout failed: {}",
        logout_output.stderr
    );

    let logout_json: Value = parse_stdout_json(&logout_output.stdout);
    assert_eq!(logout_json["loggedOut"], true);
    assert!(
        user_credentials_file(home.path()).exists(),
        "user credentials file should remain"
    );
    assert!(
        !agent_credentials_file(home.path()).exists(),
        "agent credentials file should be removed"
    );
    assert!(
        !agent_seed_path.exists(),
        "agent seed file should be removed"
    );

    let status_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "--principal", "user", "auth", "status"],
        None,
    );
    assert!(
        status_output.status.success(),
        "user status failed: {}",
        status_output.stderr
    );
    let status_json: Value = parse_stdout_json(&status_output.stdout);
    assert_eq!(status_json["principalType"], "user");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_json_logout_revoke_warning_is_machine_readable() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    state.lock().expect("state lock").logout_status = StatusCode::BAD_GATEWAY;
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "auth", "logout"],
        None,
    );
    assert!(output.status.success(), "logout failed: {}", output.stderr);

    let stdout_json = parse_stdout_json(&output.stdout);
    assert_eq!(stdout_json["loggedOut"], true);

    assert_json_warning_contains(&output.stderr, "logout_revoke_failed", "502 Bad Gateway");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_json_logout_keychain_clear_warning_is_machine_readable() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    let keychain_dir = TempDir::new().expect("temp keychain");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let store_output = run_cli_with_test_keychain(
        home.path(),
        &server.base_url,
        keychain_dir.path(),
        &["auth", "keychain", "store", "--password-stdin"],
        Some(&fixture.password),
    );
    assert!(
        store_output.status.success(),
        "keychain store failed: {}",
        store_output.stderr
    );

    replace_stored_test_keychain_secret_with_directory(keychain_dir.path());

    let output = run_cli_with_test_keychain(
        home.path(),
        &server.base_url,
        keychain_dir.path(),
        &["--json", "auth", "logout"],
        None,
    );
    assert!(output.status.success(), "logout failed: {}", output.stderr);

    let stdout_json = parse_stdout_json(&output.stdout);
    assert_eq!(stdout_json["loggedOut"], true);

    assert_json_warning_contains(
        &output.stderr,
        "logout_persisted_bootstrap_clear_failed",
        "failed to clear platform keychain entry",
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_json_logout_warning_and_cleanup_error_share_one_stderr_document() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    state.lock().expect("state lock").logout_status = StatusCode::BAD_GATEWAY;
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let socket_path = home.path().join(".worklist").join("unlock.sock");
    let fake_daemon = spawn_invalid_unlock_daemon(&socket_path);

    let output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "auth", "logout"],
        None,
    );
    fake_daemon.join().expect("join fake daemon");

    assert!(
        !output.status.success(),
        "logout unexpectedly succeeded: {}",
        output.stdout
    );
    assert!(
        output.stdout.is_empty(),
        "unexpected stdout: {}",
        output.stdout
    );

    let stderr_json = parse_stderr_json(&output.stderr);
    assert_eq!(stderr_json["warnings"][0]["code"], "logout_revoke_failed");
    assert!(
        stderr_json["warnings"][0]["message"]
            .as_str()
            .expect("warning message")
            .contains("502 Bad Gateway"),
        "unexpected stderr: {}",
        output.stderr
    );
    assert_eq!(stderr_json["error"]["code"], "unexpected");
    assert!(
        stderr_json["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("failed to clear unlock daemon session"),
        "unexpected stderr: {}",
        output.stderr
    );
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
        &[
            "--json",
            "auth",
            "unlock",
            "--ttl-seconds",
            "300",
            "--password-stdin",
        ],
        Some(&fixture.password),
    );
    assert!(
        unlock_output.status.success(),
        "unlock failed: {}",
        unlock_output.stderr
    );
    let unlock_json: Value = parse_stdout_json(&unlock_output.stdout);
    assert_eq!(unlock_json["unlocked"], true);

    let status_output = run_cli(
        home.path(),
        "https://worklist.app",
        &["--json", "auth", "status"],
        None,
    );
    assert!(
        status_output.status.success(),
        "status failed: {}",
        status_output.stderr
    );
    let status_json: Value = parse_stdout_json(&status_output.stdout);
    assert_eq!(status_json["unlockDaemon"]["active"], true);
    assert_eq!(
        status_json["apiUrlMismatch"]["currentApiUrl"],
        "https://worklist.app"
    );
    assert_eq!(
        status_json["apiUrlMismatch"]["storedApiUrl"],
        server.base_url
    );

    let _ = run_cli(home.path(), &server.base_url, &["auth", "lock"], None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_status_reports_agent_only_session() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    let agent_credentials = seed_agent_credentials(home.path(), &fixture, &server.base_url);

    let status_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "auth", "status"],
        None,
    );
    assert!(
        status_output.status.success(),
        "status failed: {}",
        status_output.stderr
    );

    let status_json: Value = parse_stdout_json(&status_output.stdout);
    assert_eq!(status_json["loggedIn"], true);
    assert_eq!(status_json["principalType"], "agent");
    assert_eq!(status_json["apiUrl"], server.base_url);
    assert_eq!(status_json["agentId"], json!(agent_credentials.agent_id));
    assert_eq!(status_json["ownerUserId"], json!(fixture.owner_user_id));
    assert_eq!(status_json["handle"], "fixture-agent");
    assert_eq!(status_json["displayName"], "Fixture Agent");
    assert_eq!(status_json["sessionState"], "active");
    assert_eq!(status_json["unlockDaemon"]["active"], false);
    assert_eq!(status_json["persistedBootstrap"]["status"], "unavailable");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_agent_register_rejects_existing_agent_for_another_api_without_overwriting() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    let existing_api_url = "https://other-worklist.example.test";
    seed_agent_credentials(home.path(), &fixture, existing_api_url);
    let agent_credentials_path = agent_credentials_file(home.path());
    let original_agent_credentials =
        std::fs::read(&agent_credentials_path).expect("read seeded agent credentials");

    let register_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "agent",
            "register",
            "--proposed-handle",
            "new-agent",
        ],
        None,
    );

    assert!(
        !register_output.status.success(),
        "agent register unexpectedly succeeded"
    );
    assert_json_error_contains(
        &register_output.stderr,
        "agent credentials already exist for https://other-worklist.example.test",
    );
    assert_eq!(
        std::fs::read(&agent_credentials_path).expect("reload agent credentials"),
        original_agent_credentials,
        "agent register should preserve the existing global agent credentials"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_json_login_requires_email_non_interactively() {
    let home = TempDir::new().expect("temp home");

    let output = run_cli(
        home.path(),
        "https://worklist.app",
        &["--json", "auth", "login"],
        None,
    );
    assert!(!output.status.success(), "login unexpectedly succeeded");
    assert!(
        output.stdout.is_empty(),
        "unexpected stdout: {}",
        output.stdout
    );

    assert_json_error_message(&output.stderr, "--json auth login requires --email");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_json_login_requires_password_stdin_non_interactively() {
    assert_json_password_stdin_required(
        &["--json", "auth", "login", "--email", "agent@example.com"],
        "--json auth login requires --password-stdin",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_json_unlock_requires_password_stdin_non_interactively() {
    assert_json_password_stdin_required(
        &["--json", "auth", "unlock"],
        "--json auth unlock requires --password-stdin",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_json_keychain_store_requires_password_stdin_non_interactively() {
    assert_json_password_stdin_required(
        &["--json", "auth", "keychain", "store"],
        "--json auth keychain store requires --password-stdin",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_json_unknown_argument_errors_are_machine_readable() {
    let home = TempDir::new().expect("temp home");

    let output = run_cli(
        home.path(),
        "https://worklist.app",
        &["--json", "--bogus"],
        None,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stdout.is_empty(),
        "unexpected stdout: {}",
        output.stdout
    );

    assert_json_error_contains(&output.stderr, "--bogus");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_json_invalid_value_errors_are_machine_readable() {
    let home = TempDir::new().expect("temp home");

    let output = run_cli(
        home.path(),
        "https://worklist.app",
        &["--json", "auth", "unlock", "--ttl-seconds", "nope"],
        None,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stdout.is_empty(),
        "unexpected stdout: {}",
        output.stdout
    );

    assert_json_error_contains(&output.stderr, "--ttl-seconds");
    assert_json_error_contains(&output.stderr, "nope");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_principal_aware_commands_fail_closed_when_both_credential_types_exist() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state.clone()).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);
    seed_agent_credentials(home.path(), &fixture, &server.base_url);

    let ambiguous_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "lists", "--raw"],
        None,
    );
    assert!(
        !ambiguous_output.status.success(),
        "ambiguous principal selection unexpectedly succeeded"
    );
    assert_json_error_contains(
        &ambiguous_output.stderr,
        "rerun with --principal user or --principal agent",
    );

    let ambiguous_status_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "auth", "status"],
        None,
    );
    assert!(
        !ambiguous_status_output.status.success(),
        "ambiguous auth status unexpectedly succeeded"
    );
    assert_json_error_contains(
        &ambiguous_status_output.stderr,
        "rerun with --principal user or --principal agent",
    );

    let user_status_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "--principal", "user", "auth", "status"],
        None,
    );
    assert!(
        user_status_output.status.success(),
        "user status failed: {}",
        user_status_output.stderr
    );
    let user_status_json: Value = parse_stdout_json(&user_status_output.stdout);
    assert_eq!(user_status_json["principalType"], "user");

    let agent_status_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "--principal", "agent", "auth", "status"],
        None,
    );
    assert!(
        agent_status_output.status.success(),
        "agent status failed: {}",
        agent_status_output.stderr
    );
    let agent_status_json: Value = parse_stdout_json(&agent_status_output.stdout);
    assert_eq!(agent_status_json["principalType"], "agent");

    let ambiguous_logout_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "auth", "logout"],
        None,
    );
    assert!(
        !ambiguous_logout_output.status.success(),
        "ambiguous logout unexpectedly succeeded"
    );
    assert_json_error_contains(
        &ambiguous_logout_output.stderr,
        "rerun with --principal user or --principal agent",
    );
    assert!(
        user_credentials_file(home.path()).exists(),
        "ambiguous logout should preserve user credentials"
    );
    assert!(
        agent_credentials_file(home.path()).exists(),
        "ambiguous logout should preserve agent credentials"
    );

    let user_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "--principal", "user", "lists", "--raw"],
        None,
    );
    assert!(
        user_output.status.success(),
        "explicit user principal failed: {}",
        user_output.stderr
    );
    {
        let state = state.lock().expect("state lock");
        assert_eq!(
            state.last_authorization_token.as_deref(),
            Some(AUTHORIZED_USER_TOKEN_LABEL)
        );
    }

    let agent_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "--principal", "agent", "lists", "--raw"],
        None,
    );
    assert!(
        agent_output.status.success(),
        "explicit agent principal failed: {}",
        agent_output.stderr
    );
    {
        let state = state.lock().expect("state lock");
        assert_eq!(
            state.last_authorization_token.as_deref(),
            Some(AUTHORIZED_AGENT_TOKEN_LABEL)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_auth_status_auto_uses_principal_matching_current_api() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, "https://other-worklist.example.test");
    seed_agent_credentials(home.path(), &fixture, &server.base_url);

    let status_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "auth", "status"],
        None,
    );
    assert!(
        status_output.status.success(),
        "status failed: {}",
        status_output.stderr
    );
    let status_json: Value = parse_stdout_json(&status_output.stdout);
    assert_eq!(status_json["principalType"], "agent");
    assert_eq!(status_json["apiUrl"], server.base_url);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_auth_status_auto_fails_closed_when_no_principal_matches_current_api() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, "https://user-worklist.example.test");
    seed_agent_credentials(home.path(), &fixture, "https://agent-worklist.example.test");

    let status_output = run_cli(
        home.path(),
        &server.base_url,
        &["--json", "auth", "status"],
        None,
    );
    assert!(
        !status_output.status.success(),
        "ambiguous status unexpectedly succeeded"
    );
    assert_json_error_contains(
        &status_output.stderr,
        "no user or agent credentials are saved for",
    );
    assert_json_error_contains(&status_output.stderr, &server.base_url);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_task_create_accepts_agent_only_credentials() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state.clone()).await;
    let home = TempDir::new().expect("temp home");
    let agent_credentials = seed_agent_credentials(home.path(), &fixture, &server.base_url);
    seed_agent_file_backed_secret(home.path(), &agent_credentials);

    let output = run_cli_with_agent_seed_file_backend(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "tasks",
            "create",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--input-file",
            write_json_file(
                home.path(),
                "agent-task-create.json",
                &json!({
                    "title": "Agent task",
                    "body": "Agent-created task body"
                }),
            )
            .to_str()
            .expect("utf8 path"),
        ],
        None,
    );

    assert!(
        output.status.success(),
        "agent-backed task create failed: {}",
        output.stderr
    );
    let created: Value = parse_stdout_json(&output.stdout);
    assert_eq!(created["title"], "Agent task");
    assert_eq!(created["bodyMarkdown"], "Agent-created task body");

    let state = state.lock().expect("state lock");
    let created_task = state
        .created_task_body
        .as_ref()
        .expect("agent-created task body recorded");
    assert_eq!(created_task.title, "Agent task");
    assert_eq!(
        created_task
            .rich_text
            .as_ref()
            .expect("created task rich text")
            .blocks[0]
            .text,
        "Agent-created task body"
    );
    assert_eq!(
        state.last_authorization_token.as_deref(),
        Some(AUTHORIZED_AGENT_TOKEN_LABEL)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_comment_create_accepts_explicit_agent_principal() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state.clone()).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);
    let agent_credentials = seed_agent_credentials(home.path(), &fixture, &server.base_url);
    seed_agent_file_backed_secret(home.path(), &agent_credentials);

    let output = run_cli_with_agent_seed_file_backend(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "--principal",
            "agent",
            "comments",
            "create",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
            "--body",
            "Agent comment",
        ],
        None,
    );

    assert!(
        output.status.success(),
        "agent-backed comment create failed: {}",
        output.stderr
    );
    let created: Value = parse_stdout_json(&output.stdout);
    assert_eq!(created["bodyMarkdown"], "Agent comment");

    let state = state.lock().expect("state lock");
    let created_comment = state
        .created_comment_body
        .as_ref()
        .expect("agent-created comment body recorded");
    assert_eq!(created_comment.content.blocks[0].text, "Agent comment");
    assert_eq!(
        state.last_authorization_token.as_deref(),
        Some(AUTHORIZED_AGENT_TOKEN_LABEL)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_decrypted_commands_fail_non_interactively_without_unlock_or_keychain() {
    let fixture = TestFixture::new();
    let state = Arc::new(Mutex::new(TestState::new(fixture.clone())));
    let server = spawn_server(state).await;
    let home = TempDir::new().expect("temp home");
    seed_credentials(home.path(), &fixture, &server.base_url);

    let task_output = run_cli(
        home.path(),
        &server.base_url,
        &[
            "--json",
            "tasks",
            "get",
            "--work-list-id",
            &fixture.work_list_id.to_string(),
            "--task-id",
            &fixture.task_id.to_string(),
        ],
        None,
    );
    assert!(
        !task_output.status.success(),
        "task get unexpectedly succeeded without any local unlock source"
    );
    assert!(
        task_output
            .stderr
            .contains("No unlocked local session or persisted bootstrap secret is available")
    );
    assert_json_error_contains(
        &task_output.stderr,
        "No unlocked local session or persisted bootstrap secret is available",
    );
}

struct TestServer {
    base_url: String,
    _task: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
struct TestAttachmentFixture {
    id: Uuid,
    file_name: String,
    content_type: String,
    plaintext_bytes: Vec<u8>,
    ciphertext_bytes: Vec<u8>,
    blob_key: Vec<u8>,
}

#[derive(Clone)]
struct TestFixture {
    password: String,
    access_token: String,
    agent_access_token: String,
    refresh_token: String,
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
    agent_work_list_key_ciphertext: String,
    work_list_payload_ciphertext: String,
    task_title_ciphertext: String,
    task_payload_ciphertext: String,
    comment_body_ciphertext: String,
    existing_task_body: TaskPayloadBody,
    existing_comment_body: CommentPayloadBody,
    text_attachment: TestAttachmentFixture,
    docx_attachment: TestAttachmentFixture,
    binary_attachment: TestAttachmentFixture,
    hostile_attachment: TestAttachmentFixture,
}

struct TestState {
    fixture: TestFixture,
    current_access_token: String,
    current_agent_access_token: String,
    current_refresh_token: String,
    last_authorization_token: Option<String>,
    logout_status: StatusCode,
    refresh_request_count: usize,
    created_task_body: Option<TaskPayloadBody>,
    updated_task_body: Option<TaskPayloadBody>,
    moved_task_body: Option<MoveTaskRequestBody>,
    archive_task_count: usize,
    unarchive_task_count: usize,
    created_comment_body: Option<CommentPayloadBody>,
    updated_comment_body: Option<CommentPayloadBody>,
    list_comments_count: usize,
    deleted_comment_audit_patch: Option<AuditPatchRequest>,
    deleted_comment_id: Option<Uuid>,
    deleted_task_audit_patch: Option<AuditPatchRequest>,
    deleted_task_id: Option<Uuid>,
    invalid_work_list_payload: bool,
    invalid_task_payload: bool,
    invalid_comment_payload: bool,
    invalid_task_attachment_metadata: bool,
    invalid_comment_attachment_metadata: bool,
    attachment_size_mismatch: bool,
    attachment_download_requests: usize,
    base_url: Option<String>,
}

impl TestState {
    fn new(fixture: TestFixture) -> Self {
        Self {
            current_access_token: fixture.access_token.clone(),
            current_agent_access_token: fixture.agent_access_token.clone(),
            current_refresh_token: fixture.refresh_token.clone(),
            last_authorization_token: None,
            logout_status: StatusCode::OK,
            refresh_request_count: 0,
            fixture,
            created_task_body: None,
            updated_task_body: None,
            moved_task_body: None,
            archive_task_count: 0,
            unarchive_task_count: 0,
            created_comment_body: None,
            updated_comment_body: None,
            list_comments_count: 0,
            deleted_comment_audit_patch: None,
            deleted_comment_id: None,
            deleted_task_audit_patch: None,
            deleted_task_id: None,
            invalid_work_list_payload: false,
            invalid_task_payload: false,
            invalid_comment_payload: false,
            invalid_task_attachment_metadata: false,
            invalid_comment_attachment_metadata: false,
            attachment_size_mismatch: false,
            attachment_download_requests: 0,
            base_url: None,
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
        let agent_key_material =
            agent_key_material_from_seed([0x5A; 32]).expect("agent key material");
        let agent_work_list_key_ciphertext = encrypt_agent_work_list_key(
            agent_key_material.recipient_public_key(),
            &work_list_id,
            &list_key,
        )
        .expect("agent work list key")
        .base64;
        let work_list_payload_ciphertext =
            encode_work_list_payload_ciphertext(&list_key).expect("work list payload");
        let text_attachment = make_attachment_fixture(
            &list_key,
            Uuid::now_v7(),
            "notes.md",
            "text/markdown",
            b"# Heading\n\nAttachment body\n".to_vec(),
            [0x44; 32],
        );
        let docx_attachment = make_attachment_fixture(
            &list_key,
            Uuid::now_v7(),
            "spec.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            docx_fixture_bytes(),
            [0x45; 32],
        );
        let binary_attachment = make_attachment_fixture(
            &list_key,
            Uuid::now_v7(),
            "spec.pdf",
            "application/pdf",
            b"%PDF-binary".to_vec(),
            [0x55; 32],
        );
        let hostile_attachment = make_attachment_fixture(
            &list_key,
            Uuid::now_v7(),
            "../../unsafe.txt",
            "text/plain",
            b"unsafe but readable\n".to_vec(),
            [0x66; 32],
        );

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
            attachments: Some(vec![
                attachment_payload_value(&text_attachment),
                attachment_payload_value(&docx_attachment),
                attachment_payload_value(&binary_attachment),
                attachment_payload_value(&hostile_attachment),
            ]),
            references: Some(vec![json_value_to_flexible(
                json!({"label": "ref", "uri": "https://example.test"}),
            )]),
            mentions: Some(vec![mentioned_user_id.to_string()]),
            client_meta: Some(FlexibleValue::Map(vec![
                (
                    FlexibleValue::Text("source".to_string()),
                    FlexibleValue::Text("fixture".to_string()),
                ),
                (
                    FlexibleValue::Text("blob".to_string()),
                    FlexibleValue::Bytes(vec![1, 2, 3, 4]),
                ),
            ])),
            recurrence_state: Some(json_value_to_flexible(json!({
                "template_id": Uuid::now_v7().to_string()
            }))),
        };
        let task_payload_ciphertext = encrypt_task_payload(
            &build_task_payload_envelope(existing_task_body.clone(), 1),
            &list_key,
        )
        .expect("task payload")
        .base64;
        let task_title_ciphertext = seal_task_title_base64("Existing task", &list_key);

        let existing_comment_body = CommentPayloadBody {
            content: plaintext_rich_text("Existing comment").expect("comment rich text"),
            mentions: Some(vec![mentioned_user_id.to_string()]),
            attachments: Some(vec![attachment_payload_value(&text_attachment)]),
            client_meta: Some(FlexibleValue::Map(vec![
                (
                    FlexibleValue::Text("source".to_string()),
                    FlexibleValue::Text("fixture".to_string()),
                ),
                (
                    FlexibleValue::Text("blob".to_string()),
                    FlexibleValue::Bytes(vec![9, 8, 7]),
                ),
            ])),
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
            agent_access_token: "agent-access-token".to_string(),
            refresh_token: "refresh-token".to_string(),
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
            agent_work_list_key_ciphertext,
            work_list_payload_ciphertext,
            task_title_ciphertext,
            task_payload_ciphertext,
            comment_body_ciphertext,
            existing_task_body,
            existing_comment_body,
            text_attachment,
            docx_attachment,
            binary_attachment,
            hostile_attachment,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTaskRequestBody {
    task_id: Option<Uuid>,
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
#[serde(rename_all = "camelCase")]
struct DeleteRequestBody {
    audit_patch: Option<AuditPatchRequest>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MoveTaskRequestBody {
    section_id: Option<Uuid>,
    insert_before_task_id: Option<Uuid>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefreshRequestBody {
    refresh_token: String,
}

#[derive(Deserialize)]
struct IncludeArchivedQuery {
    #[serde(rename = "includeArchived")]
    include_archived: Option<bool>,
}

async fn spawn_server(state: Arc<Mutex<TestState>>) -> TestServer {
    let app = Router::new()
        .route("/auth/refresh", post(refresh_session))
        .route("/auth/logout", post(logout_session))
        .route("/work-lists", get(list_work_lists))
        .route("/work-lists/{id}", get(get_work_list))
        .route("/work-lists/{id}/tasks", get(list_tasks).post(create_task))
        .route(
            "/work-lists/{id}/attachments/{attachment_id}/download",
            get(get_attachment_download),
        )
        .route(
            "/work-lists/{id}/tasks/{task_id}",
            get(get_task).patch(update_task).delete(delete_task),
        )
        .route("/work-lists/{id}/tasks/{task_id}/move", post(move_task))
        .route(
            "/work-lists/{id}/tasks/{task_id}/archive",
            post(archive_task),
        )
        .route(
            "/work-lists/{id}/tasks/{task_id}/unarchive",
            post(unarchive_task),
        )
        .route(
            "/work-lists/{id}/tasks/{task_id}/comments",
            get(list_comments).post(create_comment),
        )
        .route(
            "/work-lists/{id}/tasks/{task_id}/comments/{comment_id}",
            patch(update_comment).delete(delete_comment),
        )
        .route("/me/tasks", get(list_my_tasks))
        .route("/downloads/{attachment_id}", get(download_attachment_bytes))
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    {
        let mut guard = state.lock().expect("state lock");
        guard.base_url = Some(format!("http://{}", addr));
    }
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve app");
    });

    TestServer {
        base_url: format!("http://{}", addr),
        _task: task,
    }
}

async fn refresh_session(
    State(state): State<Arc<Mutex<TestState>>>,
    Json(payload): Json<RefreshRequestBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut state = state.lock().expect("state lock");
    assert_eq!(payload.refresh_token, state.current_refresh_token);

    state.refresh_request_count += 1;
    state.current_access_token = format!("refreshed-access-token-{}", state.refresh_request_count);
    state.current_refresh_token =
        format!("refreshed-refresh-token-{}", state.refresh_request_count);
    let access_token = state.current_access_token.clone();
    let refresh_token = state.current_refresh_token.clone();

    (
        StatusCode::OK,
        Json(json!({
            "accessToken": access_token,
            "refreshToken": refresh_token,
            "expiresIn": 3600,
            "refreshExpiresIn": 3600,
            "tokenType": "Bearer"
        })),
    )
}

async fn logout_session(
    State(state): State<Arc<Mutex<TestState>>>,
    Json(payload): Json<RefreshRequestBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let state = state.lock().expect("state lock");
    assert_eq!(payload.refresh_token, state.current_refresh_token);

    (
        state.logout_status,
        Json(json!({
            "loggedOut": state.logout_status.is_success()
        })),
    )
}

async fn list_work_lists(
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    authorize(&state, &headers);
    let state = state.lock().expect("state lock");
    (
        StatusCode::OK,
        Json(json!([work_list_summary_json(&state)])),
    )
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
        "titleCiphertext": fixture_work_list_title_ciphertext(&state.fixture.list_key),
        "descriptionCiphertext": null,
        "payloadCiphertext": work_list_payload_ciphertext(&state),
        "timezone": "UTC",
        "sectionSnapshots": [],
        "createdAt": Utc::now(),
        "updatedAt": Utc::now(),
        "membership": membership_json(&state),
        "members": [
            membership_json(&state)
        ]
    });

    (StatusCode::OK, Json(payload))
}

async fn get_attachment_download(
    Path((work_list_id, attachment_id)): Path<(Uuid, Uuid)>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    authorize(&state, &headers);
    let state = state.lock().expect("state lock");
    assert_eq!(work_list_id, state.fixture.work_list_id);
    let attachment = attachment_by_id(&state.fixture, attachment_id).expect("attachment fixture");
    let base_url = state.base_url.clone().expect("base url");

    (
        StatusCode::OK,
        Json(json!({
            "downloadUrl": format!("{base_url}/downloads/{}", attachment.id),
            "downloadHeaders": {
                "x-attachment-token": "ok"
            },
            "expiresAt": Utc::now() + Duration::minutes(5)
        })),
    )
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
                "workListTitleCiphertext": fixture_work_list_title_ciphertext(&state.fixture.list_key),
                "createdByMembershipId": state.fixture.membership_id,
                "titleCiphertext": state.fixture.task_title_ciphertext,
                "payloadCiphertext": task_payload_ciphertext(&state),
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
        "payloadCiphertext": task_payload_ciphertext(&state),
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
                "bodyCiphertext": comment_body_ciphertext(&state),
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

    let task_id = payload.task_id.expect("client-generated task id present");
    let decrypted = decrypt_task_payload(&state.fixture.list_key, &payload_bytes)
        .expect("decrypt created task");
    let decrypted_title = decrypt_task_title_for_id(&state.fixture.list_key, &title_bytes, task_id)
        .expect("decrypt created task title");
    assert_eq!(decrypted_title, decrypted.body.title);
    state.created_task_body = Some(decrypted.body.clone());

    let response = json!({
        "id": task_id,
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

    let decrypted_title = if let Some(title_ciphertext) = payload.title_ciphertext.as_ref() {
        let title_bytes = decode_b64(title_ciphertext);
        let title_proof =
            compute_payload_proof(&title_bytes, &state.fixture.binding_key).expect("title proof");
        assert_eq!(
            payload.title_ciphertext_proof.as_deref(),
            Some(title_proof.as_str())
        );
        Some(
            decrypt_task_title_for_id(&state.fixture.list_key, &title_bytes, task_id)
                .expect("decrypt updated task title"),
        )
    } else {
        None
    };

    let decrypted = decrypt_task_payload(&state.fixture.list_key, &payload_bytes)
        .expect("decrypt updated task");
    if let Some(decrypted_title) = decrypted_title {
        assert_eq!(decrypted_title, decrypted.body.title);
    }
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

async fn move_task(
    Path((work_list_id, task_id)): Path<(Uuid, Uuid)>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
    Json(payload): Json<MoveTaskRequestBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    authorize(&state, &headers);
    let mut state = state.lock().expect("state lock");
    assert_eq!(work_list_id, state.fixture.work_list_id);
    assert_eq!(task_id, state.fixture.task_id);
    state.moved_task_body = Some(payload.clone());

    let response = json!({
        "id": state.fixture.task_id,
        "workListId": state.fixture.work_list_id,
        "createdByMembershipId": state.fixture.membership_id,
        "titleCiphertext": state.fixture.task_title_ciphertext,
        "payloadCiphertext": task_payload_ciphertext(&state),
        "sectionId": payload.section_id,
        "priority": null,
        "position": "moved",
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

async fn archive_task(
    Path((work_list_id, task_id)): Path<(Uuid, Uuid)>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
    _payload: Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    authorize(&state, &headers);
    let mut state = state.lock().expect("state lock");
    assert_eq!(work_list_id, state.fixture.work_list_id);
    assert_eq!(task_id, state.fixture.task_id);
    state.archive_task_count += 1;

    let response = json!({
        "id": state.fixture.task_id,
        "workListId": state.fixture.work_list_id,
        "createdByMembershipId": state.fixture.membership_id,
        "titleCiphertext": state.fixture.task_title_ciphertext,
        "payloadCiphertext": task_payload_ciphertext(&state),
        "sectionId": null,
        "priority": null,
        "position": "a",
        "dueAt": null,
        "startAt": null,
        "completedAt": null,
        "archivedAt": Utc::now(),
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

async fn unarchive_task(
    Path((work_list_id, task_id)): Path<(Uuid, Uuid)>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
    _payload: Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    authorize(&state, &headers);
    let mut state = state.lock().expect("state lock");
    assert_eq!(work_list_id, state.fixture.work_list_id);
    assert_eq!(task_id, state.fixture.task_id);
    state.unarchive_task_count += 1;

    let response = json!({
        "id": state.fixture.task_id,
        "workListId": state.fixture.work_list_id,
        "createdByMembershipId": state.fixture.membership_id,
        "titleCiphertext": state.fixture.task_title_ciphertext,
        "payloadCiphertext": task_payload_ciphertext(&state),
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

async fn delete_task(
    Path((work_list_id, task_id)): Path<(Uuid, Uuid)>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
    payload: Option<Json<DeleteRequestBody>>,
) -> StatusCode {
    authorize(&state, &headers);
    let mut state = state.lock().expect("state lock");
    assert_eq!(work_list_id, state.fixture.work_list_id);
    assert_eq!(task_id, state.fixture.task_id);
    state.deleted_task_audit_patch = delete_request_audit_patch(payload);
    state.deleted_task_id = Some(task_id);
    StatusCode::NO_CONTENT
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

async fn list_comments(
    Path((work_list_id, task_id)): Path<(Uuid, Uuid)>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    authorize(&state, &headers);
    let mut state = state.lock().expect("state lock");
    assert_eq!(work_list_id, state.fixture.work_list_id);
    assert_eq!(task_id, state.fixture.task_id);
    state.list_comments_count += 1;

    if state.deleted_comment_id == Some(state.fixture.comment_id) {
        return (StatusCode::OK, Json(json!([])));
    }

    (
        StatusCode::OK,
        Json(json!([
            {
                "id": state.fixture.comment_id,
                "taskId": state.fixture.task_id,
                "authorMembershipId": state.fixture.membership_id,
                "bodyCiphertext": comment_body_ciphertext(&state),
                "createdAt": Utc::now(),
                "updatedAt": Utc::now()
            }
        ])),
    )
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

async fn delete_comment(
    Path((work_list_id, task_id, comment_id)): Path<(Uuid, Uuid, Uuid)>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
    payload: Option<Json<DeleteRequestBody>>,
) -> StatusCode {
    authorize(&state, &headers);
    let mut state = state.lock().expect("state lock");
    assert_eq!(work_list_id, state.fixture.work_list_id);
    assert_eq!(task_id, state.fixture.task_id);
    assert_eq!(comment_id, state.fixture.comment_id);
    state.deleted_comment_audit_patch = delete_request_audit_patch(payload);
    state.deleted_comment_id = Some(comment_id);
    StatusCode::NO_CONTENT
}

fn delete_request_audit_patch(
    payload: Option<Json<DeleteRequestBody>>,
) -> Option<AuditPatchRequest> {
    payload.and_then(|Json(payload)| payload.audit_patch)
}

fn delete_input_audit_patch(
    field: &str,
    payload_ciphertext: &str,
    payload_ciphertext_proof: &str,
) -> AuditPatchRequest {
    AuditPatchRequest {
        fields: vec![AuditPatchFieldRequest {
            field: field.to_string(),
            change_kind: "clear".to_string(),
            before_scalar: None,
            after_scalar: None,
            before_ciphertext_digest: None,
            after_ciphertext_digest: None,
        }],
        payload_ciphertext: payload_ciphertext.to_string(),
        payload_ciphertext_proof: payload_ciphertext_proof.to_string(),
        payload_version: 1,
    }
}

fn delete_input(
    field: &str,
    payload_ciphertext: &str,
    payload_ciphertext_proof: &str,
) -> (Value, AuditPatchRequest) {
    let audit_patch = delete_input_audit_patch(field, payload_ciphertext, payload_ciphertext_proof);
    let input = json!({
        "auditPatch": audit_patch.clone()
    });

    (input, audit_patch)
}

async fn download_attachment_bytes(
    Path(attachment_id): Path<Uuid>,
    State(state): State<Arc<Mutex<TestState>>>,
    headers: HeaderMap,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let token = headers
        .get("x-attachment-token")
        .and_then(|value| value.to_str().ok())
        .expect("attachment token header");
    assert_eq!(token, "ok");

    let mut state = state.lock().expect("state lock");
    state.attachment_download_requests += 1;
    let mut ciphertext = attachment_by_id(&state.fixture, attachment_id)
        .expect("attachment fixture")
        .ciphertext_bytes
        .clone();
    if state.attachment_size_mismatch {
        ciphertext.pop();
    }
    (StatusCode::OK, HeaderMap::new(), ciphertext)
}

fn run_cli(home: &std::path::Path, api_url: &str, args: &[&str], stdin: Option<&str>) -> CliOutput {
    run_cli_in_dir(home, home, api_url, args, stdin)
}

fn run_cli_with_closed_stdout(
    home: &std::path::Path,
    api_url: &str,
    args: &[&str],
    stdin: Option<&str>,
) -> CliOutput {
    let binary = assert_cmd::cargo::cargo_bin("worklist");
    let mut command = std::process::Command::new(binary);
    command.env("HOME", home);
    command.current_dir(home);
    command.arg("--api-url").arg(api_url);
    command.args(args);
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command.spawn().expect("spawn cli");
    drop(child.stdout.take().expect("stdout pipe"));

    if let Some(stdin) = stdin {
        let mut child_stdin = child.stdin.take().expect("stdin pipe");
        child_stdin
            .write_all(stdin.as_bytes())
            .expect("write stdin");
    }

    let output = child.wait_with_output().expect("wait for cli");
    CliOutput {
        status: output.status,
        stdout: String::from_utf8(output.stdout).expect("stdout utf8"),
        stderr: String::from_utf8(output.stderr).expect("stderr utf8"),
    }
}

fn run_cli_with_test_keychain(
    home: &std::path::Path,
    api_url: &str,
    keychain_dir: &std::path::Path,
    args: &[&str],
    stdin: Option<&str>,
) -> CliOutput {
    let mut command = Command::cargo_bin("worklist").expect("binary");
    command.env("HOME", home);
    command.env("WORKLIST_TEST_KEYCHAIN_DIR", keychain_dir);
    command.current_dir(home);
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

fn run_cli_with_agent_seed_file_backend(
    home: &std::path::Path,
    api_url: &str,
    args: &[&str],
    stdin: Option<&str>,
) -> CliOutput {
    let mut command = Command::cargo_bin("worklist").expect("binary");
    command.env("HOME", home);
    command.env("WORKLIST_AGENT_SEED_FILE_ONLY", "1");
    command.current_dir(home);
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

fn run_cli_in_dir(
    home: &std::path::Path,
    current_dir: &std::path::Path,
    api_url: &str,
    args: &[&str],
    stdin: Option<&str>,
) -> CliOutput {
    let mut command = Command::cargo_bin("worklist").expect("binary");
    command.env("HOME", home);
    command.current_dir(current_dir);
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
    seed_credentials_with_expiry(
        home,
        fixture,
        api_url,
        Utc::now() + Duration::hours(1),
        Utc::now() + Duration::days(1),
    );
}

fn seed_agent_credentials(
    home: &std::path::Path,
    fixture: &TestFixture,
    api_url: &str,
) -> AgentCredentials {
    let credentials = AgentCredentials {
        api_url: api_url.to_string(),
        agent_id: Uuid::now_v7(),
        owner_user_id: Some(fixture.owner_user_id),
        handle: Some("fixture-agent".to_string()),
        display_name: Some("Fixture Agent".to_string()),
        access_token: Some(fixture.agent_access_token.clone()),
        access_expires_at: Some(Utc::now() + Duration::hours(1)),
    };

    let config_dir = home.join(".worklist");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    let path = config_dir.join("agent.json");
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&credentials).expect("serialize agent creds"),
    )
    .expect("write agent creds");

    credentials
}

fn seed_agent_file_backed_secret(
    home: &std::path::Path,
    credentials: &AgentCredentials,
) -> std::path::PathBuf {
    let path = agent_seed_file_path(home, credentials);
    std::fs::write(&path, [0x5A; 32]).expect("write agent seed");
    path
}

fn agent_seed_file_path(
    home: &std::path::Path,
    credentials: &AgentCredentials,
) -> std::path::PathBuf {
    let entry_name = format!(
        "{}::{}",
        normalize_api_url(&credentials.api_url),
        credentials.agent_id
    );
    let file_name = format!(
        "agent-seed-{}.bin",
        URL_SAFE_NO_PAD.encode(Sha256::digest(entry_name.as_bytes()))
    );
    home.join(".worklist").join(file_name)
}

fn user_credentials_file(home: &std::path::Path) -> std::path::PathBuf {
    home.join(".worklist").join("credentials.json")
}

fn agent_credentials_file(home: &std::path::Path) -> std::path::PathBuf {
    home.join(".worklist").join("agent.json")
}

fn seed_credentials_with_expiry(
    home: &std::path::Path,
    fixture: &TestFixture,
    api_url: &str,
    access_expires_at: DateTime<Utc>,
    refresh_expires_at: DateTime<Utc>,
) {
    let credentials = Credentials {
        api_url: api_url.to_string(),
        access_token: fixture.access_token.clone(),
        refresh_token: fixture.refresh_token.clone(),
        access_expires_at,
        refresh_expires_at,
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
    let mut state = state.lock().expect("state lock");
    let expected_user = format!("Bearer {}", state.current_access_token);
    let expected_agent = format!("Bearer {}", state.current_agent_access_token);

    if token == expected_user {
        state.last_authorization_token = Some(AUTHORIZED_USER_TOKEN_LABEL.to_string());
        return;
    }
    if token == expected_agent {
        state.last_authorization_token = Some(AUTHORIZED_AGENT_TOKEN_LABEL.to_string());
        return;
    }

    panic!(
        "unexpected authorization header: {token} (expected {expected_user} or {expected_agent})"
    );
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
        "payloadCiphertext": task_payload_ciphertext(state),
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

fn fixture_work_list_title_ciphertext(list_key: &SymmetricKey) -> String {
    seal_work_list_title("Fixture Work List", list_key)
        .expect("seal work list title")
        .base64
}

fn seal_task_title_base64(value: &str, list_key: &SymmetricKey) -> String {
    seal_task_title(value, list_key)
        .expect("seal task title")
        .base64
}

fn work_list_summary_json(state: &TestState) -> serde_json::Value {
    json!({
        "id": state.fixture.work_list_id,
        "ownerUserId": state.fixture.owner_user_id,
        "workspaceId": state.fixture.workspace_id,
        "titleCiphertext": fixture_work_list_title_ciphertext(&state.fixture.list_key),
        "descriptionCiphertext": null,
        "payloadCiphertext": work_list_payload_ciphertext(state),
        "timezone": "UTC",
        "sectionSnapshots": [],
        "createdAt": Utc::now(),
        "updatedAt": Utc::now(),
        "membership": membership_json(state)
    })
}

fn membership_json(state: &TestState) -> serde_json::Value {
    let work_list_key_ciphertext =
        if state.last_authorization_token.as_deref() == Some(AUTHORIZED_AGENT_TOKEN_LABEL) {
            &state.fixture.agent_work_list_key_ciphertext
        } else {
            &state.fixture.work_list_key_ciphertext
        };

    json!({
        "id": state.fixture.membership_id,
        "userId": state.fixture.owner_user_id,
        "userEmail": "fixture@example.test",
        "userName": "Fixture",
        "userAvatarColor": "#111111",
        "role": "owner",
        "status": "active",
        "workListKeyCiphertext": work_list_key_ciphertext,
        "recipientCiphertext": null,
        "invitePackageCiphertext": null,
        "saltMember": null,
        "expiresAt": null,
        "joinedAt": Utc::now(),
        "payloadBindingKey": null
    })
}

fn work_list_payload_ciphertext(state: &TestState) -> String {
    if state.invalid_work_list_payload {
        "invalid-work-list-payload".to_string()
    } else {
        state.fixture.work_list_payload_ciphertext.clone()
    }
}

fn task_payload_ciphertext(state: &TestState) -> String {
    if state.invalid_task_payload {
        return "invalid-task-payload".to_string();
    }

    if state.invalid_task_attachment_metadata {
        let mut body = state.fixture.existing_task_body.clone();
        body.attachments = Some(vec![json_value_to_flexible(json!({
            "id": state.fixture.text_attachment.id.to_string()
        }))]);
        return encrypt_task_payload(
            &build_task_payload_envelope(body, 1),
            &state.fixture.list_key,
        )
        .expect("task payload with invalid attachment metadata")
        .base64;
    }

    state.fixture.task_payload_ciphertext.clone()
}

fn comment_body_ciphertext(state: &TestState) -> String {
    if state.invalid_comment_payload {
        return "invalid-comment-payload".to_string();
    }

    if state.invalid_comment_attachment_metadata {
        let mut body = state.fixture.existing_comment_body.clone();
        body.attachments = Some(vec![json_value_to_flexible(json!({
            "id": state.fixture.text_attachment.id.to_string()
        }))]);
        return encrypt_comment_payload(
            &build_comment_payload_envelope(body, 1),
            &state.fixture.list_key,
        )
        .expect("comment payload with invalid attachment metadata")
        .base64;
    }

    state.fixture.comment_body_ciphertext.clone()
}

fn attachment_by_id(fixture: &TestFixture, attachment_id: Uuid) -> Option<&TestAttachmentFixture> {
    [
        &fixture.text_attachment,
        &fixture.docx_attachment,
        &fixture.binary_attachment,
        &fixture.hostile_attachment,
    ]
    .into_iter()
    .find(|attachment| attachment.id == attachment_id)
}

fn make_attachment_fixture(
    list_key: &SymmetricKey,
    attachment_id: Uuid,
    file_name: &str,
    content_type: &str,
    plaintext_bytes: Vec<u8>,
    file_key_bytes: [u8; 32],
) -> TestAttachmentFixture {
    let file_key = SymmetricKey::new(file_key_bytes);
    let ciphertext_bytes =
        encrypt_attachment_ciphertext(&file_key, &plaintext_bytes).expect("attachment ciphertext");
    let blob_key =
        encode_attachment_blob_key(list_key, attachment_id, &file_key, &ciphertext_bytes)
            .expect("attachment blob key");
    TestAttachmentFixture {
        id: attachment_id,
        file_name: file_name.to_string(),
        content_type: content_type.to_string(),
        plaintext_bytes,
        ciphertext_bytes,
        blob_key,
    }
}

fn docx_fixture_bytes() -> Vec<u8> {
    const DOCX_FIXTURE_BASE64: &str = "UEsDBBQAAAAIAOp8kVzXeYTq8QAAALgBAAATAAAAW0NvbnRlbnRfVHlwZXNdLnhtbH2QzU7DMBCE730Ky9cqccoBIZSkB36OwKE8wMreJFb9J69b2rdn00KREOVozXwz62nXB+/EHjPZGDq5qhspMOhobBg7+b55ru6koALBgIsBO3lEkut+0W6OCUkwHKiTUynpXinSE3qgOiYMrAwxeyj8zKNKoLcworppmlulYygYSlXmDNkvhGgfcYCdK+LpwMr5loyOpHg4e+e6TkJKzmoorKt9ML+Kqq+SmsmThyabaMkGqa6VzOL1jh/0lSfK1qB4g1xewLNRfcRslIl65xmu/0/649o4DFbjhZ/TUo4aiXh77+qL4sGG71+06jR8/wlQSwMEFAAAAAgA6nyRXCAbhuqyAAAALgEAAAsAAABfcmVscy8ucmVsc43Puw6CMBQG4J2naM4uBQdjDIXFmLAafICmPZRGeklbL7y9HRzEODie23fyN93TzOSOIWpnGdRlBQStcFJbxeAynDZ7IDFxK/nsLDJYMELXFs0ZZ57yTZy0jyQjNjKYUvIHSqOY0PBYOo82T0YXDE+5DIp6Lq5cId1W1Y6GTwPagpAVS3rJIPSyBjIsHv/h3ThqgUcnbgZt+vHlayPLPChMDB4uSCrf7TKzQHNKuorZvgBQSwMEFAAAAAgA6nyRXDbicKixAAAADAEAABEAAAB3b3JkL2RvY3VtZW50LnhtbG2PMQ+CMBCFd35F012KDsYQKIPGuLlo4lrpKST0rmmryL+3xbixfHkv9/Lurmo+ZmBvcL4nrPk6LzgDbEn3+Kz59XJc7TjzQaFWAyHUfALPG5lVY6mpfRnAwGID+nKseReCLYXwbQdG+ZwsYJw9yBkVonVPMZLT1lEL3scFZhCbotgKo3rkMmMstt5JT0nOxsoIlxDkCVQ6qhLJJLqZdjF8OO9vLFUtxpP47Unq/4f8AlBLAQIUAxQAAAAIAOp8kVzXeYTq8QAAALgBAAATAAAAAAAAAAAAAACAAQAAAABbQ29udGVudF9UeXBlc10ueG1sUEsBAhQDFAAAAAgA6nyRXCAbhuqyAAAALgEAAAsAAAAAAAAAAAAAAIABIgEAAF9yZWxzLy5yZWxzUEsBAhQDFAAAAAgA6nyRXDbicKixAAAADAEAABEAAAAAAAAAAAAAAIAB/QEAAHdvcmQvZG9jdW1lbnQueG1sUEsFBgAAAAADAAMAuQAAAN0CAAAAAA==";

    base64::engine::general_purpose::STANDARD
        .decode(DOCX_FIXTURE_BASE64)
        .expect("decode docx fixture")
}

fn encrypt_attachment_ciphertext(
    file_key: &SymmetricKey,
    plaintext_bytes: &[u8],
) -> worklist_client_core::PublicResult<Vec<u8>> {
    StrongBoxKeyRing::new(file_key.clone())
        .strong_box()
        .encrypt(plaintext_bytes, ATTACHMENT_BLOB_CONTEXT)
        .map_err(|err| {
            worklist_client_core::PublicError::crypto(format!(
                "failed to seal attachment bytes: {err}"
            ))
        })
}

fn encode_attachment_blob_key(
    list_key: &SymmetricKey,
    attachment_id: Uuid,
    file_key: &SymmetricKey,
    ciphertext_bytes: &[u8],
) -> worklist_client_core::PublicResult<Vec<u8>> {
    let blob_ref = AttachmentBlobRef {
        version: ATTACHMENT_BLOB_REF_VERSION,
        object_key: format!("workspaces/test/attachments/{attachment_id}"),
        ciphertext_bytes: u64::try_from(ciphertext_bytes.len()).expect("ciphertext length"),
        file_key: file_key.as_bytes().to_vec(),
        enc_context: ATTACHMENT_BLOB_CONTEXT_LABEL.to_string(),
    };
    let plaintext = serialize_to_cbor(&blob_ref)?;
    let sealed = StrongBoxKeyRing::new(list_key.clone())
        .strong_box()
        .encrypt(plaintext, ATTACHMENT_REF_CONTEXT)
        .expect("seal attachment ref");
    SealedPayload::new(sealed).to_bytes()
}

fn attachment_payload_value(attachment: &TestAttachmentFixture) -> FlexibleValue {
    FlexibleValue::Map(vec![
        (
            FlexibleValue::Text("id".to_string()),
            FlexibleValue::Text(attachment.id.to_string()),
        ),
        (
            FlexibleValue::Text("file_name".to_string()),
            FlexibleValue::Text(attachment.file_name.clone()),
        ),
        (
            FlexibleValue::Text("content_type".to_string()),
            FlexibleValue::Text(attachment.content_type.clone()),
        ),
        (
            FlexibleValue::Text("size_bytes".to_string()),
            FlexibleValue::Integer(
                u64::try_from(attachment.plaintext_bytes.len())
                    .expect("plaintext length")
                    .into(),
            ),
        ),
        (
            FlexibleValue::Text("blob_key".to_string()),
            FlexibleValue::Bytes(attachment.blob_key.clone()),
        ),
    ])
}

fn parse_stdout_json(stdout: &str) -> Value {
    serde_json::from_str(stdout).expect("stdout JSON")
}

fn parse_stderr_json(stderr: &str) -> Value {
    serde_json::from_str(stderr).expect("stderr JSON")
}

fn assert_json_error_message(stderr: &str, expected_message: &str) {
    let error_json = parse_stderr_json(stderr);
    assert_eq!(error_json["error"]["code"], "validation");
    assert_eq!(error_json["error"]["message"], expected_message);
}

fn assert_json_error_contains(stderr: &str, expected_fragment: &str) {
    let error_json = parse_stderr_json(stderr);
    assert_eq!(error_json["error"]["code"], "validation");
    assert!(
        error_json["error"]["message"]
            .as_str()
            .expect("error message")
            .contains(expected_fragment),
        "unexpected stderr: {stderr}"
    );
}

fn assert_json_warning_contains(stderr: &str, expected_code: &str, expected_fragment: &str) {
    let stderr_json = parse_stderr_json(stderr);
    assert_eq!(stderr_json["warnings"][0]["code"], expected_code);
    assert!(
        stderr_json["warnings"][0]["message"]
            .as_str()
            .expect("warning message")
            .contains(expected_fragment),
        "unexpected stderr: {stderr}"
    );
}

fn assert_json_password_stdin_required(args: &[&str], expected_message: &str) {
    let home = TempDir::new().expect("temp home");
    let output = run_cli(home.path(), "https://worklist.app", args, None);

    assert!(!output.status.success(), "command unexpectedly succeeded");
    assert!(
        output.stdout.is_empty(),
        "unexpected stdout: {}",
        output.stdout
    );
    assert_json_error_message(&output.stderr, expected_message);
}

#[cfg(unix)]
fn spawn_invalid_unlock_daemon(socket_path: &FsPath) -> std::thread::JoinHandle<()> {
    use std::os::unix::net::UnixListener;

    if socket_path.exists() {
        std::fs::remove_file(socket_path).expect("remove stale fake daemon socket");
    }

    let listener = UnixListener::bind(socket_path).expect("bind fake daemon socket");
    let socket_path = socket_path.to_path_buf();

    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fake daemon connection");
        let mut request = Vec::new();
        stream
            .read_to_end(&mut request)
            .expect("read fake daemon request");
        stream
            .write_all(b"{not valid json")
            .expect("write fake daemon response");
        drop(stream);
        drop(listener);
        let _ = std::fs::remove_file(socket_path);
    })
}

fn replace_stored_test_keychain_secret_with_directory(keychain_dir: &FsPath) {
    let secret_path = std::fs::read_dir(keychain_dir)
        .expect("list keychain dir")
        .map(|entry| entry.expect("dir entry").path())
        .next()
        .expect("stored secret path");
    std::fs::remove_file(&secret_path).expect("remove stored secret");
    std::fs::create_dir(&secret_path).expect("replace stored secret with directory");
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
