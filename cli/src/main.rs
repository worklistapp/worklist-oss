#![cfg_attr(test, allow(clippy::unwrap_used))]

mod unlock_daemon;

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use rpassword::prompt_password;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;
use uuid::Uuid;
use worklist_client_api::{
    CommentResponse, CreateCommentRequest, CreateTaskRequest, CurrentUserResponse,
    DashboardStatsResponse, MyTaskResponse, PublicApiClient, TaskResponse, UpdateCommentRequest,
    UpdateTaskRequest, WorkListDetailResponse, WorkListResponse,
};
use worklist_client_auth::{
    Credentials, UnlockMode, auth_response_to_credentials, clear_credentials, credentials_path,
    load_credentials, load_credentials_for_url, login, logout, normalize_api_url, save_credentials,
};
use worklist_client_core::PublicResult;
use worklist_client_crypto::{
    CommentPayloadBody, CryptoCapability, TaskPayloadBody, build_comment_payload_envelope,
    build_task_payload_envelope, compute_payload_proof, decode_sealed_blob,
    decrypt_comment_payload, decrypt_task_payload, decrypt_user_data_key, decrypt_work_list_key,
    decrypt_work_list_payload, derive_payload_binding_key, derive_work_list_key,
    encrypt_comment_payload, encrypt_task_payload, plaintext_rich_text, seal_text_value,
};

#[derive(Parser, Debug)]
#[command(
    name = "worklist",
    version,
    about = "CLI for working with Worklist tasks, comments, and encrypted workspace data"
)]
struct Cli {
    /// API base URL.
    #[arg(
        long,
        env = "WORKLIST_API_URL",
        default_value = "https://worklist.app",
        global = true
    )]
    api_url: String,

    /// Output format for data commands.
    #[arg(long, value_enum, default_value_t = OutputFormat::Json, global = true)]
    format: OutputFormat,

    #[arg(long, hide = true)]
    serve_unlock_daemon: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum, Default)]
enum OutputFormat {
    Table,
    #[default]
    Json,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show CLI metadata and capability summary.
    Info,
    /// Authenticate and manage local session state.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Fetch the current user profile.
    Me,
    /// List work lists for the current user.
    Lists {
        #[arg(long)]
        verbose: bool,
    },
    /// Manage tasks.
    Tasks {
        #[command(subcommand)]
        command: TasksCommand,
    },
    /// Show dashboard statistics.
    Stats,
    /// Inspect and decrypt work list payload data.
    Inspect {
        work_list_id: Uuid,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Create and update encrypted comments.
    Comments {
        #[command(subcommand)]
        command: CommentsCommand,
    },
}

#[derive(Subcommand, Debug)]
enum TasksCommand {
    /// List tasks.
    List {
        #[arg(long)]
        work_list_id: Option<Uuid>,
        #[arg(long)]
        include_completed: bool,
        #[arg(long)]
        all: bool,
    },
    /// Create a new task in a work list.
    Create(TaskCreateArgs),
    /// Update an existing task's encrypted title/body.
    Update(TaskUpdateArgs),
}

#[derive(Subcommand, Debug)]
enum CommentsCommand {
    /// Create a new comment on a task.
    Create(CommentCreateArgs),
    /// Update an existing comment.
    Update(CommentUpdateArgs),
}

#[derive(Args, Debug)]
struct TaskCreateArgs {
    #[arg(long)]
    work_list_id: Uuid,
    #[arg(long)]
    title: Option<String>,
    #[arg(long)]
    body: Option<String>,
    #[arg(long)]
    input_file: Option<PathBuf>,
    #[arg(long)]
    input_stdin: bool,
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Args, Debug)]
struct TaskUpdateArgs {
    #[arg(long)]
    work_list_id: Uuid,
    #[arg(long)]
    task_id: Uuid,
    #[arg(long)]
    title: Option<String>,
    #[arg(long)]
    body: Option<String>,
    #[arg(long)]
    input_file: Option<PathBuf>,
    #[arg(long)]
    input_stdin: bool,
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Args, Debug)]
struct CommentCreateArgs {
    #[arg(long)]
    work_list_id: Uuid,
    #[arg(long)]
    task_id: Uuid,
    #[arg(long)]
    body: Option<String>,
    #[arg(long)]
    input_file: Option<PathBuf>,
    #[arg(long)]
    input_stdin: bool,
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Args, Debug)]
struct CommentUpdateArgs {
    #[arg(long)]
    work_list_id: Uuid,
    #[arg(long)]
    task_id: Uuid,
    #[arg(long)]
    comment_id: Uuid,
    #[arg(long)]
    body: Option<String>,
    #[arg(long)]
    input_file: Option<PathBuf>,
    #[arg(long)]
    input_stdin: bool,
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaskCreateInput {
    title: String,
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaskUpdateInput {
    title: Option<String>,
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommentInput {
    body: String,
}

#[derive(Debug, Clone, Copy)]
enum JsonInputSource<'a> {
    File(&'a Path),
    Stdin,
}

impl<'a> JsonInputSource<'a> {
    fn label(self) -> &'a str {
        match self {
            Self::File(_) => "file",
            Self::Stdin => "stdin",
        }
    }
}

#[derive(Subcommand, Debug)]
enum AuthCommand {
    /// Login and persist credentials.
    Login {
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Unlock the decrypted data key in a local in-memory daemon.
    Unlock {
        #[arg(long, default_value_t = 8 * 60 * 60)]
        ttl_seconds: u64,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Shut down the local unlock daemon.
    Lock,
    /// Logout and clear stored credentials.
    Logout,
    /// Show local credential status.
    Status,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(err) = run(cli).await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> PublicResult<()> {
    if let Some(socket_path) = cli.serve_unlock_daemon.as_deref() {
        return unlock_daemon::serve(socket_path).await;
    }

    let Some(command) = cli.command else {
        return Err(worklist_client_core::PublicError::validation(
            "a command is required",
        ));
    };

    match command {
        Command::Info => {
            let client = PublicApiClient::new(&cli.api_url);
            let payload = json!({
                "apiBaseUrl": client.base_url(),
                "commandName": "worklist",
                "automationProfile": "agent_task_management",
                "authUnlockModes": [
                    UnlockMode::SingleCommand.as_str(),
                    UnlockMode::Daemon.as_str(),
                ],
                "cryptoCapabilities": [
                    CryptoCapability::DataKeyUnwrap.as_str(),
                    CryptoCapability::WorkListKeyDecrypt.as_str(),
                    CryptoCapability::PayloadSeal.as_str(),
                    CryptoCapability::PayloadProof.as_str(),
                ],
                "note": "This CLI is intended for agent-friendly task and comment workflows against Worklist.",
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .expect("serializing CLI metadata should succeed")
            );
            Ok(())
        }
        Command::Auth { command } => match command {
            AuthCommand::Login {
                email,
                password_stdin,
            } => cmd_login(&cli.api_url, email, password_stdin).await,
            AuthCommand::Unlock {
                ttl_seconds,
                password_stdin,
            } => cmd_unlock(&cli.api_url, ttl_seconds, password_stdin).await,
            AuthCommand::Lock => cmd_lock(),
            AuthCommand::Logout => cmd_logout(&cli.api_url).await,
            AuthCommand::Status => cmd_status(&cli.api_url),
        },
        Command::Me => cmd_me(&cli.api_url, cli.format).await,
        Command::Lists { verbose } => cmd_lists(&cli.api_url, cli.format, verbose).await,
        Command::Tasks { command } => cmd_tasks(&cli.api_url, cli.format, command).await,
        Command::Stats => cmd_stats(&cli.api_url, cli.format).await,
        Command::Inspect {
            work_list_id,
            password_stdin,
        } => cmd_inspect(&cli.api_url, cli.format, work_list_id, password_stdin).await,
        Command::Comments { command } => cmd_comments(&cli.api_url, command).await,
    }
}

async fn cmd_login(
    api_url: &str,
    email_flag: Option<String>,
    password_stdin: bool,
) -> PublicResult<()> {
    if let Some(credentials) = load_credentials_for_url(api_url)?
        && !credentials.is_refresh_expired()
    {
        println!("Already logged in as {} ({})", credentials.email, api_url);
        return Ok(());
    }

    let email = match email_flag {
        Some(email) => email,
        None => prompt("Email: ")?,
    };
    if email.is_empty() {
        return Err(worklist_client_core::PublicError::validation(
            "email is required",
        ));
    }

    let password = read_required_password(password_stdin, None)?;

    println!("Authenticating...");
    let client = reqwest::Client::new();
    let auth_response = login(&client, api_url, &email, &password).await?;
    let credentials = auth_response_to_credentials(api_url, auth_response);
    save_credentials(&credentials)?;

    println!("Logged in as {}", credentials.email);
    println!("Credentials saved to {}", credentials_path()?.display());
    Ok(())
}

async fn cmd_unlock(api_url: &str, ttl_seconds: u64, password_stdin: bool) -> PublicResult<()> {
    let credentials = require_logged_in_credentials(api_url)?;
    let password = read_required_password(
        password_stdin,
        Some("Password required to unlock the local daemon."),
    )?;
    let data_key = decrypt_user_data_key(&password, &credentials.data_key_ciphertext)?;
    let session_key = daemon_session_key(api_url, &credentials)?;
    unlock_daemon::unlock(&session_key, &data_key, ttl_seconds)?;
    println!("Unlocked local daemon for {} seconds.", ttl_seconds);
    Ok(())
}

fn cmd_lock() -> PublicResult<()> {
    unlock_daemon::lock()?;
    println!("Locked local daemon.");
    Ok(())
}

async fn cmd_logout(api_url: &str) -> PublicResult<()> {
    let credentials = match load_credentials_for_url(api_url)? {
        Some(credentials) => credentials,
        None => {
            println!("Not logged in.");
            return Ok(());
        }
    };

    let client = reqwest::Client::new();
    if let Err(err) = logout(&client, api_url, &credentials.refresh_token).await {
        eprintln!("warning: failed to revoke token on server: {err}");
    }

    clear_credentials()?;
    let session_key = daemon_session_key(api_url, &credentials)?;
    unlock_daemon::clear_session(&session_key)?;
    println!("Logged out successfully.");
    Ok(())
}

fn cmd_status(api_url: &str) -> PublicResult<()> {
    match load_credentials()? {
        Some(credentials) => {
            println!("Logged in as: {}", credentials.email);
            println!("API URL: {}", credentials.api_url);
            println!("User ID: {}", credentials.user_id);
            println!(
                "Access token expires: {}",
                credentials
                    .access_expires_at
                    .format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!(
                "Refresh token expires: {}",
                credentials
                    .refresh_expires_at
                    .format("%Y-%m-%d %H:%M:%S UTC")
            );

            let status_api_url = credentials.api_url.clone();
            if status_api_url != normalize_api_url(api_url) {
                println!("\nNote: Stored credentials are for a different API URL.");
                println!("Stored: {}", status_api_url);
                println!("Current: {}", api_url);
            }

            if credentials.is_refresh_expired() {
                println!("\nWarning: Session has expired. Please login again.");
            } else if credentials.is_access_expired() {
                println!("\nNote: Access token has expired but will be refreshed automatically.");
            }

            let unlock_status = unlock_daemon::unlock_status(Some(&daemon_session_key(
                &status_api_url,
                &credentials,
            )?))?;
            if unlock_status.unlocked {
                if let Some(expires_at_unix) = unlock_status.expires_at_unix {
                    println!("\nUnlock daemon: active until unix {}", expires_at_unix);
                } else {
                    println!("\nUnlock daemon: active");
                }
            } else {
                println!("\nUnlock daemon: inactive");
            }
        }
        None => {
            println!("Not logged in.");
            println!(
                "Credentials would be stored at: {}",
                credentials_path()?.display()
            );
            println!("Unlock daemon: inactive for current target");
        }
    }

    Ok(())
}

async fn cmd_me(api_url: &str, format: OutputFormat) -> PublicResult<()> {
    let mut client = get_authenticated_client(api_url)?;
    let user = client.get_me().await?;
    print_user(&user, format);
    Ok(())
}

async fn cmd_lists(api_url: &str, format: OutputFormat, verbose: bool) -> PublicResult<()> {
    let mut client = get_authenticated_client(api_url)?;
    let lists = client.list_work_lists().await?;
    if lists.is_empty() {
        println!("No work lists found.");
        return Ok(());
    }
    print_work_lists(&lists, format, verbose);
    Ok(())
}

async fn cmd_tasks(api_url: &str, format: OutputFormat, command: TasksCommand) -> PublicResult<()> {
    match command {
        TasksCommand::List {
            work_list_id,
            include_completed,
            all,
        } => cmd_tasks_list(api_url, format, work_list_id, include_completed, all).await,
        TasksCommand::Create(args) => cmd_tasks_create(api_url, args).await,
        TasksCommand::Update(args) => cmd_tasks_update(api_url, args).await,
    }
}

async fn cmd_tasks_list(
    api_url: &str,
    format: OutputFormat,
    work_list_id: Option<Uuid>,
    include_completed: bool,
    all: bool,
) -> PublicResult<()> {
    let mut client = get_authenticated_client(api_url)?;

    if all || work_list_id.is_none() {
        let response = client.get_my_tasks(Some(100), None).await?;
        let tasks: Vec<_> = if include_completed {
            response.tasks
        } else {
            response
                .tasks
                .into_iter()
                .filter(|task| !task.is_completed)
                .collect()
        };

        if tasks.is_empty() {
            println!("No tasks found.");
            return Ok(());
        }

        print_my_tasks(&tasks, format);
        return Ok(());
    }

    if let Some(work_list_id) = work_list_id {
        let response = client.get_tasks(work_list_id, false).await?;
        let tasks: Vec<_> = if include_completed {
            response.tasks
        } else {
            response
                .tasks
                .into_iter()
                .filter(|task| !task.is_completed)
                .collect()
        };

        if tasks.is_empty() {
            println!("No tasks found in this work list.");
            return Ok(());
        }

        print_tasks(&tasks, format);
    }

    Ok(())
}

async fn cmd_tasks_create(api_url: &str, args: TaskCreateArgs) -> PublicResult<()> {
    let work_list_id = args.work_list_id;
    let input = resolve_task_create_input(&args)?;
    let normalized_title = input.title.trim();
    if normalized_title.is_empty() {
        return Err(worklist_client_core::PublicError::validation(
            "title is required",
        ));
    }

    let credentials = require_logged_in_credentials(api_url)?;

    let mut client = PublicApiClient::with_credentials(api_url, credentials.clone());
    let work_list = client.get_work_list(work_list_id).await?;

    let list_key = load_list_key(
        api_url,
        &credentials,
        work_list_id,
        &work_list.work_list.membership.work_list_key_ciphertext,
        args.password_stdin,
        "Password required to create encrypted task payloads.",
    )?;
    let binding_key = derive_payload_binding_key(&list_key)?;

    let task_body = TaskPayloadBody {
        title: normalized_title.to_string(),
        rich_text: input.body.as_deref().and_then(plaintext_rich_text),
        checklist: None,
        attachments: None,
        references: None,
        mentions: None,
        client_meta: None,
        recurrence_state: None,
    };
    let envelope = build_task_payload_envelope(task_body, 1);
    let payload_ciphertext = encrypt_task_payload(&envelope, &list_key)?;
    let title_ciphertext = seal_text_value(normalized_title)?;
    let payload_proof = compute_payload_proof(&payload_ciphertext.bytes, &binding_key)?;
    let title_proof = compute_payload_proof(&title_ciphertext.bytes, &binding_key)?;

    let created = client
        .create_task(
            work_list_id,
            &CreateTaskRequest {
                title_ciphertext: title_ciphertext.base64,
                title_ciphertext_proof: title_proof,
                payload_ciphertext: payload_ciphertext.base64,
                payload_ciphertext_proof: payload_proof,
                attachment_ids: Vec::new(),
                priority: None,
                due_at: None,
                section_id: None,
            },
        )
        .await?;

    println!(
        "{}",
        serde_json::to_string_pretty(&created).expect("serializing created task should succeed")
    );
    Ok(())
}

async fn cmd_tasks_update(api_url: &str, args: TaskUpdateArgs) -> PublicResult<()> {
    let work_list_id = args.work_list_id;
    let task_id = args.task_id;
    let input = resolve_task_update_input(&args)?;
    if input.title.is_none() && input.body.is_none() {
        return Err(worklist_client_core::PublicError::validation(
            "provide at least one of --title or --body",
        ));
    }

    let credentials = require_logged_in_credentials(api_url)?;

    let mut client = PublicApiClient::with_credentials(api_url, credentials.clone());
    let work_list = client.get_work_list(work_list_id).await?;
    let task_detail = client.get_task(work_list_id, task_id).await?;

    let list_key = load_list_key(
        api_url,
        &credentials,
        work_list_id,
        &work_list.work_list.membership.work_list_key_ciphertext,
        args.password_stdin,
        "Password required to update encrypted task payloads.",
    )?;
    let binding_key = derive_payload_binding_key(&list_key)?;

    let payload_bytes = decode_sealed_blob(&task_detail.task.payload_ciphertext)?;
    let existing_payload = decrypt_task_payload(&list_key, &payload_bytes)?;

    let existing_body = existing_payload.body;
    let next_title = input
        .title
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| existing_body.title.clone());
    let next_rich_text = match input.body.as_deref() {
        Some(value) if value.trim().is_empty() => None,
        Some(value) => plaintext_rich_text(value),
        None => existing_body.rich_text.clone(),
    };

    let next_body = TaskPayloadBody {
        title: next_title.clone(),
        rich_text: next_rich_text,
        checklist: existing_body.checklist,
        attachments: existing_body.attachments,
        references: existing_body.references,
        mentions: existing_body.mentions,
        client_meta: existing_body.client_meta,
        recurrence_state: existing_body.recurrence_state,
    };
    let envelope = build_task_payload_envelope(next_body, 1);
    let payload_ciphertext = encrypt_task_payload(&envelope, &list_key)?;
    let payload_proof = compute_payload_proof(&payload_ciphertext.bytes, &binding_key)?;

    let mut request = UpdateTaskRequest {
        payload_ciphertext: Some(payload_ciphertext.base64),
        payload_ciphertext_proof: Some(payload_proof),
        ..UpdateTaskRequest::default()
    };

    if let Some(new_title) = input.title.as_deref() {
        let normalized_title = new_title.trim();
        if normalized_title.is_empty() {
            return Err(worklist_client_core::PublicError::validation(
                "title cannot be empty",
            ));
        }
        let title_ciphertext = seal_text_value(normalized_title)?;
        let title_proof = compute_payload_proof(&title_ciphertext.bytes, &binding_key)?;
        request.title_ciphertext = Some(title_ciphertext.base64);
        request.title_ciphertext_proof = Some(title_proof);
    }

    let updated = client.update_task(work_list_id, task_id, &request).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&updated).expect("serializing updated task should succeed")
    );
    Ok(())
}

async fn cmd_stats(api_url: &str, format: OutputFormat) -> PublicResult<()> {
    let mut client = get_authenticated_client(api_url)?;
    let stats = client.get_dashboard_stats().await?;
    print_stats(&stats, format);
    Ok(())
}

async fn cmd_comments(api_url: &str, command: CommentsCommand) -> PublicResult<()> {
    match command {
        CommentsCommand::Create(args) => cmd_comments_create(api_url, args).await,
        CommentsCommand::Update(args) => cmd_comments_update(api_url, args).await,
    }
}

async fn cmd_comments_create(api_url: &str, args: CommentCreateArgs) -> PublicResult<()> {
    let work_list_id = args.work_list_id;
    let task_id = args.task_id;
    let input = resolve_comment_input(
        args.body.as_deref(),
        args.input_file.as_deref(),
        args.input_stdin,
        args.password_stdin,
    )?;
    let normalized_body = input.body.trim();
    if normalized_body.is_empty() {
        return Err(worklist_client_core::PublicError::validation(
            "comment body is required",
        ));
    }

    let credentials = require_logged_in_credentials(api_url)?;

    let mut client = PublicApiClient::with_credentials(api_url, credentials.clone());
    let work_list = client.get_work_list(work_list_id).await?;

    let list_key = load_list_key(
        api_url,
        &credentials,
        work_list_id,
        &work_list.work_list.membership.work_list_key_ciphertext,
        args.password_stdin,
        "Password required to create encrypted comments.",
    )?;
    let binding_key = derive_payload_binding_key(&list_key)?;
    let rich_text = plaintext_rich_text(normalized_body)
        .ok_or_else(|| worklist_client_core::PublicError::validation("comment body is required"))?;
    let envelope = build_comment_payload_envelope(
        CommentPayloadBody {
            content: rich_text,
            mentions: None,
            attachments: None,
            client_meta: None,
        },
        1,
    );
    let body_ciphertext = encrypt_comment_payload(&envelope, &list_key)?;
    let body_proof = compute_payload_proof(&body_ciphertext.bytes, &binding_key)?;

    let created: CommentResponse = client
        .create_comment(
            work_list_id,
            task_id,
            &CreateCommentRequest {
                body_ciphertext: body_ciphertext.base64,
                body_ciphertext_proof: body_proof,
            },
        )
        .await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&created).expect("serializing created comment should succeed")
    );
    Ok(())
}

async fn cmd_comments_update(api_url: &str, args: CommentUpdateArgs) -> PublicResult<()> {
    let work_list_id = args.work_list_id;
    let task_id = args.task_id;
    let comment_id = args.comment_id;
    let input = resolve_comment_input(
        args.body.as_deref(),
        args.input_file.as_deref(),
        args.input_stdin,
        args.password_stdin,
    )?;
    let normalized_body = input.body.trim();
    if normalized_body.is_empty() {
        return Err(worklist_client_core::PublicError::validation(
            "comment body is required",
        ));
    }

    let credentials = require_logged_in_credentials(api_url)?;

    let mut client = PublicApiClient::with_credentials(api_url, credentials.clone());
    let work_list = client.get_work_list(work_list_id).await?;
    let task_detail = client.get_task(work_list_id, task_id).await?;

    let list_key = load_list_key(
        api_url,
        &credentials,
        work_list_id,
        &work_list.work_list.membership.work_list_key_ciphertext,
        args.password_stdin,
        "Password required to update encrypted comments.",
    )?;
    let binding_key = derive_payload_binding_key(&list_key)?;
    let rich_text = plaintext_rich_text(normalized_body)
        .ok_or_else(|| worklist_client_core::PublicError::validation("comment body is required"))?;

    let existing_comment = task_detail
        .comments
        .iter()
        .find(|comment| comment.id == comment_id)
        .ok_or_else(|| worklist_client_core::PublicError::validation("comment not found"))?;
    let existing_body_ciphertext = decode_sealed_blob(&existing_comment.body_ciphertext)?;
    let existing_payload = decrypt_comment_payload(&list_key, &existing_body_ciphertext)?;

    let envelope = build_comment_payload_envelope(
        CommentPayloadBody {
            content: rich_text,
            mentions: existing_payload.body.mentions,
            attachments: existing_payload.body.attachments,
            client_meta: existing_payload.body.client_meta,
        },
        1,
    );
    let body_ciphertext = encrypt_comment_payload(&envelope, &list_key)?;
    let body_proof = compute_payload_proof(&body_ciphertext.bytes, &binding_key)?;

    let updated: CommentResponse = client
        .update_comment(
            work_list_id,
            task_id,
            comment_id,
            &UpdateCommentRequest {
                body_ciphertext: Some(body_ciphertext.base64),
                body_ciphertext_proof: Some(body_proof),
            },
        )
        .await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&updated).expect("serializing updated comment should succeed")
    );
    Ok(())
}

async fn cmd_inspect(
    api_url: &str,
    format: OutputFormat,
    work_list_id: Uuid,
    password_stdin: bool,
) -> PublicResult<()> {
    let credentials = require_logged_in_credentials(api_url)?;

    let mut client = PublicApiClient::with_credentials(api_url, credentials.clone());
    let work_list = client.get_work_list(work_list_id).await?;

    let work_list_key = load_list_key(
        api_url,
        &credentials,
        work_list_id,
        &work_list.work_list.membership.work_list_key_ciphertext,
        password_stdin,
        "Password required to decrypt data.",
    )?;
    let payload_bytes = decode_sealed_blob(&work_list.work_list.payload_ciphertext)?;
    let envelope: serde_json::Value = decrypt_work_list_payload(&work_list_key, &payload_bytes)?;

    print_inspect_result(&work_list, &envelope, format);
    Ok(())
}

fn get_authenticated_client(api_url: &str) -> PublicResult<PublicApiClient> {
    let credentials = require_logged_in_credentials(api_url)?;

    if credentials.is_refresh_expired() {
        return Err(worklist_client_core::PublicError::validation(
            "session expired - run 'worklist auth login' to authenticate",
        ));
    }

    Ok(PublicApiClient::with_credentials(api_url, credentials))
}

fn require_logged_in_credentials(api_url: &str) -> PublicResult<Credentials> {
    load_credentials_for_url(api_url)?.ok_or_else(|| {
        worklist_client_core::PublicError::validation(
            "not logged in - run 'worklist auth login' first",
        )
    })
}

fn resolve_list_key(
    data_key: &worklist_client_crypto::SymmetricKey,
    work_list_id: Uuid,
    membership_ciphertext: &str,
) -> PublicResult<worklist_client_crypto::SymmetricKey> {
    if membership_ciphertext.trim().is_empty() {
        return derive_work_list_key(data_key, &work_list_id);
    }

    let work_list_key_bytes = decode_sealed_blob(membership_ciphertext)?;
    decrypt_work_list_key(data_key, &work_list_key_bytes)
}

fn unlock_list_key(
    password: &str,
    data_key_ciphertext: &str,
    work_list_id: Uuid,
    membership_ciphertext: &str,
) -> PublicResult<worklist_client_crypto::SymmetricKey> {
    let data_key = decrypt_user_data_key(password, data_key_ciphertext)?;
    resolve_list_key(&data_key, work_list_id, membership_ciphertext)
}

fn load_list_key(
    api_url: &str,
    credentials: &Credentials,
    work_list_id: Uuid,
    membership_ciphertext: &str,
    password_stdin: bool,
    prompt_message: &str,
) -> PublicResult<worklist_client_crypto::SymmetricKey> {
    let session_key = daemon_session_key(api_url, credentials)?;
    if !password_stdin
        && let Some(data_key) = unlock_daemon::fetch_data_key(&session_key)?
        && let Ok(list_key) = resolve_list_key(&data_key, work_list_id, membership_ciphertext)
    {
        return Ok(list_key);
    }

    let password = read_required_password(password_stdin, Some(prompt_message))?;
    unlock_list_key(
        &password,
        &credentials.data_key_ciphertext,
        work_list_id,
        membership_ciphertext,
    )
}

fn resolve_task_create_input(args: &TaskCreateArgs) -> PublicResult<TaskCreateInput> {
    if let Some(input) = load_structured_input::<TaskCreateInput>(
        args.input_file.as_deref(),
        args.input_stdin,
        args.password_stdin,
    )? {
        return Ok(input);
    }

    let title = args
        .title
        .as_deref()
        .map(str::to_owned)
        .ok_or_else(|| worklist_client_core::PublicError::validation("title is required"))?;

    Ok(TaskCreateInput {
        title,
        body: args.body.as_deref().map(str::to_owned),
    })
}

fn resolve_task_update_input(args: &TaskUpdateArgs) -> PublicResult<TaskUpdateInput> {
    if let Some(input) = load_structured_input::<TaskUpdateInput>(
        args.input_file.as_deref(),
        args.input_stdin,
        args.password_stdin,
    )? {
        return Ok(input);
    }

    Ok(TaskUpdateInput {
        title: args.title.as_deref().map(str::to_owned),
        body: args.body.as_deref().map(str::to_owned),
    })
}

fn resolve_comment_input(
    body: Option<&str>,
    input_file: Option<&Path>,
    input_stdin: bool,
    password_stdin: bool,
) -> PublicResult<CommentInput> {
    if let Some(input) =
        load_structured_input::<CommentInput>(input_file, input_stdin, password_stdin)?
    {
        return Ok(input);
    }

    let body = body
        .map(str::to_owned)
        .ok_or_else(|| worklist_client_core::PublicError::validation("comment body is required"))?;

    Ok(CommentInput { body })
}

fn load_structured_input<T: DeserializeOwned>(
    input_file: Option<&Path>,
    input_stdin: bool,
    password_stdin: bool,
) -> PublicResult<Option<T>> {
    let source = select_json_input_source(input_file, input_stdin, password_stdin)?;
    let Some(source) = source else {
        return Ok(None);
    };

    let contents = read_json_input(source)?;
    parse_json_input(&contents, source.label()).map(Some)
}

fn select_json_input_source<'a>(
    input_file: Option<&'a Path>,
    input_stdin: bool,
    password_stdin: bool,
) -> PublicResult<Option<JsonInputSource<'a>>> {
    if input_file.is_some() && input_stdin {
        return Err(worklist_client_core::PublicError::validation(
            "use only one of --input-file or --input-stdin",
        ));
    }

    if input_stdin && password_stdin {
        return Err(worklist_client_core::PublicError::validation(
            "--input-stdin cannot be combined with --password-stdin",
        ));
    }

    Ok(match (input_file, input_stdin) {
        (Some(path), false) => Some(JsonInputSource::File(path)),
        (None, true) => Some(JsonInputSource::Stdin),
        (None, false) => None,
        (Some(_), true) => unreachable!("validated mutually exclusive input flags"),
    })
}

fn read_json_input(source: JsonInputSource<'_>) -> PublicResult<String> {
    match source {
        JsonInputSource::File(path) => fs::read_to_string(path).map_err(|err| {
            worklist_client_core::PublicError::unexpected(format!(
                "failed to read input file {}: {err}",
                path.display()
            ))
        }),
        JsonInputSource::Stdin => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input).map_err(|err| {
                worklist_client_core::PublicError::unexpected(format!(
                    "failed to read input from stdin: {err}"
                ))
            })?;
            Ok(input)
        }
    }
}

fn parse_json_input<T: DeserializeOwned>(contents: &str, source: &str) -> PublicResult<T> {
    serde_json::from_str(contents).map_err(|err| {
        worklist_client_core::PublicError::validation(format!(
            "invalid JSON input from {source}: {err}"
        ))
    })
}

fn daemon_session_key(
    api_url: &str,
    credentials: &Credentials,
) -> PublicResult<unlock_daemon::SessionKey> {
    unlock_daemon::session_key(
        api_url,
        credentials.user_id,
        &credentials.data_key_ciphertext,
    )
}

fn prompt(label: &str) -> PublicResult<String> {
    print!("{label}");
    io::stdout().flush().map_err(|err| {
        worklist_client_core::PublicError::unexpected(format!("failed to flush stdout: {err}"))
    })?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|err| {
        worklist_client_core::PublicError::unexpected(format!("failed to read input: {err}"))
    })?;

    Ok(input.trim().to_string())
}

fn read_password(label: &str) -> PublicResult<String> {
    prompt_password(label).map_err(|err| {
        worklist_client_core::PublicError::unexpected(format!("failed to read password: {err}"))
    })
}

fn read_password_from_stdin() -> PublicResult<String> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).map_err(|err| {
        worklist_client_core::PublicError::unexpected(format!(
            "failed to read password from stdin: {err}"
        ))
    })?;
    Ok(input.trim().to_string())
}

fn read_required_password(
    password_stdin: bool,
    prompt_message: Option<&str>,
) -> PublicResult<String> {
    let password = if password_stdin {
        read_password_from_stdin()?
    } else {
        if let Some(prompt_message) = prompt_message {
            println!("{prompt_message}");
        }
        read_password("Password: ")?
    };

    if password.is_empty() {
        return Err(worklist_client_core::PublicError::validation(
            "password is required",
        ));
    }

    Ok(password)
}

fn print_user(user: &CurrentUserResponse, format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(user).expect("serializing user should succeed")
            );
        }
        OutputFormat::Table => {
            println!("User Information");
            println!("{}", "-".repeat(40));
            println!("ID:          {}", user.id);
            println!("Email:       {}", user.email);
            println!("Name:        {}", user.name);
            println!("Timezone:    {}", user.timezone);
            println!("Theme:       {}", user.theme_preference);
            println!(
                "Verified:    {}",
                if user.email_verified { "Yes" } else { "No" }
            );
        }
    }
}

fn print_work_lists(lists: &[WorkListResponse], format: OutputFormat, verbose: bool) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(lists).expect("serializing work lists should succeed")
            );
        }
        OutputFormat::Table => {
            if verbose {
                print_work_lists_verbose(lists);
            } else {
                print_work_lists_compact(lists);
            }
        }
    }
}

fn print_work_lists_compact(lists: &[WorkListResponse]) {
    println!("{:<36}  {:<10}  {:<8}  Updated", "ID", "Role", "Sections");
    println!("{}", "-".repeat(80));

    for list in lists {
        let updated = list.updated_at.format("%Y-%m-%d %H:%M").to_string();
        println!(
            "{:<36}  {:<10}  {:<8}  {}",
            list.id,
            list.membership.role,
            list.section_snapshots.len(),
            updated
        );
    }

    println!("\nTotal: {} work list(s)", lists.len());
}

fn print_work_lists_verbose(lists: &[WorkListResponse]) {
    for (index, list) in lists.iter().enumerate() {
        if index > 0 {
            println!();
        }

        println!("Work List: {}", list.id);
        println!("{}", "-".repeat(50));
        println!("  Workspace:     {}", list.workspace_id);
        println!("  Owner:         {}", list.owner_user_id);
        println!("  Timezone:      {}", list.timezone);
        println!("  Sections:      {}", list.section_snapshots.len());
        println!("  Your role:     {}", list.membership.role);
        println!("  Your status:   {}", list.membership.status);
        println!(
            "  Created:       {}",
            list.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!(
            "  Updated:       {}",
            list.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
    }

    println!("\nTotal: {} work list(s)", lists.len());
}

fn print_tasks(tasks: &[TaskResponse], format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(tasks).expect("serializing tasks should succeed")
            );
        }
        OutputFormat::Table => {
            println!(
                "{:<36}  {:<3}  {:<10}  {:<10}  Comments",
                "ID", "Pri", "Due", "Status"
            );
            println!("{}", "-".repeat(80));

            for task in tasks {
                let priority = task
                    .priority
                    .map(|value| value.to_string())
                    .unwrap_or_default();
                let due = task
                    .due_at
                    .map(|value| value.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "-".to_string());
                let status = if task.is_completed {
                    "Done"
                } else if task.archived_at.is_some() {
                    "Archived"
                } else {
                    "Active"
                };

                println!(
                    "{:<36}  {:<3}  {:<10}  {:<10}  {}",
                    task.id, priority, due, status, task.comment_count
                );
            }

            println!("\nTotal: {} task(s)", tasks.len());
        }
    }
}

fn print_my_tasks(tasks: &[MyTaskResponse], format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(tasks).expect("serializing my tasks should succeed")
            );
        }
        OutputFormat::Table => {
            println!(
                "{:<36}  {:<36}  {:<3}  {:<10}  Status",
                "Task ID", "Work List ID", "Pri", "Due"
            );
            println!("{}", "-".repeat(100));

            for task in tasks {
                let priority = task
                    .priority
                    .map(|value| value.to_string())
                    .unwrap_or_default();
                let due = task
                    .due_at
                    .map(|value| value.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "-".to_string());
                let status = if task.is_completed { "Done" } else { "Active" };

                println!(
                    "{:<36}  {:<36}  {:<3}  {:<10}  {}",
                    task.id, task.work_list_id, priority, due, status
                );
            }

            println!("\nTotal: {} task(s)", tasks.len());
        }
    }
}

fn print_stats(stats: &DashboardStatsResponse, format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(stats).expect("serializing stats should succeed")
            );
        }
        OutputFormat::Table => {
            println!("Dashboard Statistics");
            println!("{}", "-".repeat(30));
            println!("Overdue:        {}", stats.tasks_overdue);
            println!("Due today:      {}", stats.tasks_due_today);
            println!("Due this week:  {}", stats.tasks_due_this_week);
            println!("Completed:      {}", stats.completed);
        }
    }
}

fn print_inspect_result(
    work_list: &WorkListDetailResponse,
    payload: &serde_json::Value,
    format: OutputFormat,
) {
    match format {
        OutputFormat::Json => {
            let result = serde_json::json!({
                "work_list_id": work_list.work_list.id,
                "workspace_id": work_list.work_list.workspace_id,
                "owner_user_id": work_list.work_list.owner_user_id,
                "timezone": work_list.work_list.timezone,
                "created_at": work_list.work_list.created_at,
                "updated_at": work_list.work_list.updated_at,
                "membership": {
                    "id": work_list.work_list.membership.id,
                    "role": work_list.work_list.membership.role,
                    "status": work_list.work_list.membership.status,
                },
                "members_count": work_list.members.len(),
                "decrypted_payload": payload,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&result)
                    .expect("serializing inspect result should succeed")
            );
        }
        OutputFormat::Table => {
            println!("Work List Inspection");
            println!("{}", "=".repeat(60));
            println!("ID:          {}", work_list.work_list.id);
            println!("Workspace:   {}", work_list.work_list.workspace_id);
            println!("Owner:       {}", work_list.work_list.owner_user_id);
            println!("Timezone:    {}", work_list.work_list.timezone);
            println!("Members:     {}", work_list.members.len());
            println!("Your role:   {}", work_list.work_list.membership.role);
            println!("Your status: {}", work_list.work_list.membership.status);
            println!(
                "Created:     {}",
                work_list
                    .work_list
                    .created_at
                    .format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!(
                "Updated:     {}",
                work_list
                    .work_list
                    .updated_at
                    .format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!();
            println!("Decrypted Payload");
            println!("{}", "-".repeat(60));
            println!(
                "{}",
                serde_json::to_string_pretty(payload)
                    .expect("serializing decrypted payload should succeed")
            );
        }
    }
}
