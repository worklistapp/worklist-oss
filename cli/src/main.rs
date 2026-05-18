#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use uuid::Uuid;
use worklist_client_api::{
    AgentSummaryResponse, ApproveAgentEnrollmentRequest, CurrentUserResponse,
    DashboardStatsResponse, DeleteCommentRequest, DeleteTaskRequest, TaskDetailResponse,
    TaskResponse, WorkListDetailResponse, WorkListResponse,
};
use worklist_client_auth::{
    AgentCredentials, Credentials, PersistedDataKeyStatus, PrincipalCredentials,
    PrincipalSelection, UnlockMode, agent_credentials_path, auth_response_to_credentials,
    clear_agent_credentials, clear_agent_seed, clear_credentials, credentials_path,
    fetch_agent_enrollment, generate_agent_key_material, load_agent_credentials, load_credentials,
    load_credentials_for_url, load_principal_credentials_for_url, login, logout, normalize_api_url,
    persisted_data_key_status, register_agent, save_agent_credentials, save_agent_seed,
    save_credentials,
};
use worklist_client_core::{PublicError, PublicResult};
use worklist_client_crypto::CryptoCapability;
use worklist_client_runtime::{
    AgentComment, AgentTaskDetail, AgentTaskSummary, AgentWorkListDetail, AgentWorkListSummary,
    ArchiveTaskArgs, CommentInput, CreateCommentArgs, CreateTaskArgs, DeleteCommentArgs,
    DeleteTaskArgs, MoveTaskArgs, MoveTaskInput, ReadableAttachment, RuntimeClient, SessionKey,
    TaskCreateInput, TaskUpdateInput, UnarchiveTaskArgs, UnlockStatus, UpdateCommentArgs,
    UpdateTaskArgs, clear_session, lock, serve, session_key, unlock_status,
};

type CliResult<T> = Result<T, CliError>;

#[derive(Debug)]
enum CliError {
    BrokenPipe,
    Public(PublicError),
    PublicWithWarnings {
        error: PublicError,
        warnings: Vec<WarningResult>,
    },
}

impl std::error::Error for CliError {}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(err) = self.public_error() {
            err.fmt(f)
        } else {
            write!(f, "broken pipe")
        }
    }
}

impl From<PublicError> for CliError {
    fn from(value: PublicError) -> Self {
        Self::Public(value)
    }
}

impl CliError {
    fn public_error(&self) -> Option<&PublicError> {
        match self {
            Self::BrokenPipe => None,
            Self::Public(err) | Self::PublicWithWarnings { error: err, .. } => Some(err),
        }
    }

    fn code(&self) -> &'static str {
        match self.public_error() {
            None => "broken_pipe",
            Some(PublicError::Validation(_)) => "validation",
            Some(PublicError::Crypto(_)) => "crypto",
            Some(PublicError::Unexpected(_)) => "unexpected",
        }
    }

    fn warnings(&self) -> &[WarningResult] {
        match self {
            Self::PublicWithWarnings { warnings, .. } => warnings,
            _ => &[],
        }
    }

    fn with_warnings(error: PublicError, warnings: &[WarningResult]) -> Self {
        Self::PublicWithWarnings {
            error,
            warnings: warnings.to_vec(),
        }
    }

    fn error_result(&self) -> ErrorResult {
        ErrorResult {
            code: self.code(),
            message: self.to_string(),
        }
    }
}

macro_rules! print {
    () => {
        write_stdout(format_args!(""))?
    };
    ($($arg:tt)*) => {
        write_stdout(format_args!($($arg)*))?
    };
}

macro_rules! println {
    () => {
        write_stdout_line(format_args!(""))?
    };
    ($($arg:tt)*) => {
        write_stdout_line(format_args!($($arg)*))?
    };
}

fn write_stdout(args: fmt::Arguments<'_>) -> CliResult<()> {
    write_to_stream(io::stdout().lock(), args, "print to", "stdout", true)
}

fn write_stdout_line(args: fmt::Arguments<'_>) -> CliResult<()> {
    write_line_to_stream(io::stdout().lock(), args, "print to", "stdout", true)
}

fn write_stderr_line(args: fmt::Arguments<'_>) -> CliResult<()> {
    write_line_to_stream(io::stderr().lock(), args, "print to", "stderr", false)
}

fn flush_stdout() -> CliResult<()> {
    io::stdout()
        .lock()
        .flush()
        .map_err(|err| map_stream_error(err, "flush", "stdout", true))
}

fn write_to_stream<W: Write>(
    mut stream: W,
    args: fmt::Arguments<'_>,
    action: &str,
    stream_name: &str,
    broken_pipe_is_success: bool,
) -> CliResult<()> {
    stream
        .write_fmt(args)
        .map_err(|err| map_stream_error(err, action, stream_name, broken_pipe_is_success))
}

fn write_line_to_stream<W: Write>(
    mut stream: W,
    args: fmt::Arguments<'_>,
    action: &str,
    stream_name: &str,
    broken_pipe_is_success: bool,
) -> CliResult<()> {
    stream
        .write_fmt(args)
        .map_err(|err| map_stream_error(err, action, stream_name, broken_pipe_is_success))?;
    stream
        .write_all(b"\n")
        .map_err(|err| map_stream_error(err, action, stream_name, broken_pipe_is_success))
}

fn map_stream_error(
    err: io::Error,
    action: &str,
    stream_name: &str,
    broken_pipe_is_success: bool,
) -> CliError {
    if broken_pipe_is_success && err.kind() == io::ErrorKind::BrokenPipe {
        CliError::BrokenPipe
    } else {
        CliError::Public(PublicError::unexpected(format!(
            "failed to {action} {stream_name}: {err}"
        )))
    }
}

fn print_pretty_json<T: Serialize + ?Sized>(value: &T, context: &str) -> CliResult<()> {
    let output = serde_json::to_string_pretty(value).expect(context);
    println!("{output}");
    Ok(())
}

fn print_pretty_json_stderr<T: Serialize + ?Sized>(value: &T, context: &str) -> CliResult<()> {
    let output = serde_json::to_string_pretty(value).expect(context);
    write_stderr_line(format_args!("{output}"))
}

#[derive(Parser, Debug)]
#[command(
    name = "worklist",
    version,
    about = "CLI for working with Worklist tasks, comments, and decrypted workspace data"
)]
struct Cli {
    #[arg(
        long,
        env = "WORKLIST_API_URL",
        default_value = "https://worklist.app",
        global = true
    )]
    api_url: String,

    #[arg(long, global = true)]
    json: bool,

    #[arg(long, value_enum, global = true)]
    principal: Option<PrincipalArg>,

    #[arg(long, hide = true)]
    serve_unlock_daemon: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum PrincipalArg {
    User,
    Agent,
}

impl From<PrincipalArg> for PrincipalSelection {
    fn from(value: PrincipalArg) -> Self {
        match value {
            PrincipalArg::User => PrincipalSelection::User,
            PrincipalArg::Agent => PrincipalSelection::Agent,
        }
    }
}

impl OutputFormat {
    #[must_use]
    fn from_raw_args(args: &[OsString]) -> Self {
        if args.iter().any(|arg| arg == OsStr::new("--json")) {
            Self::Json
        } else {
            Self::Table
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResult {
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct StderrEnvelope<'a> {
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    warnings: &'a [WarningResult],
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorResult>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WarningResult {
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginResult {
    logged_in: bool,
    already_logged_in: bool,
    email: String,
    api_url: String,
    credentials_path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentRegisterResult {
    registered: bool,
    agent_id: Uuid,
    enrollment_code: Option<String>,
    fingerprint: String,
    api_url: String,
    credentials_path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UnlockResult {
    unlocked: bool,
    mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LogoutResult {
    logged_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistedBootstrapEnvelope {
    persisted_bootstrap: PersistedBootstrapStatus,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistedBootstrapStatus {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UnlockDaemonStatusResult {
    active: bool,
    expires_at_unix: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiUrlMismatch {
    stored_api_url: String,
    current_api_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LoggedInStatusResult {
    logged_in: bool,
    principal_type: &'static str,
    api_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token_expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token_expires_at: Option<String>,
    #[serde(skip_serializing)]
    access_token_expires_display: Option<String>,
    #[serde(skip_serializing)]
    refresh_token_expires_display: Option<String>,
    session_state: &'static str,
    api_url_mismatch: Option<ApiUrlMismatch>,
    unlock_daemon: UnlockDaemonStatusResult,
    persisted_bootstrap: PersistedBootstrapStatus,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LoggedOutStatusResult {
    logged_in: bool,
    credentials_path: String,
    unlock_daemon: UnlockDaemonStatusResult,
    persisted_bootstrap: PersistedBootstrapStatus,
}

enum AuthStatusResult {
    LoggedIn(Box<LoggedInStatusResult>),
    LoggedOut(LoggedOutStatusResult),
}

#[derive(Subcommand, Debug)]
enum Command {
    Info,
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    Me,
    Lists {
        #[arg(long)]
        verbose: bool,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long, hide = true)]
        raw: bool,
        #[command(subcommand)]
        command: Option<ListsCommand>,
    },
    Tasks {
        #[command(subcommand)]
        command: TasksCommand,
    },
    Stats,
    #[command(hide = true)]
    Inspect {
        work_list_id: Uuid,
        #[arg(long)]
        password_stdin: bool,
    },
    Comments {
        #[command(subcommand)]
        command: CommentsCommand,
    },
}

#[derive(Subcommand, Debug)]
enum AgentCommand {
    Register {
        #[arg(long)]
        proposed_handle: Option<String>,
    },
    Approve {
        code: String,
        #[arg(long)]
        handle: String,
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        password_stdin: bool,
    },
    List,
    Revoke {
        selector: String,
    },
}

#[derive(Subcommand, Debug)]
enum ListsCommand {
    Get {
        work_list_id: Uuid,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long, hide = true)]
        raw: bool,
    },
}

#[derive(Subcommand, Debug)]
enum TasksCommand {
    List {
        #[arg(long)]
        work_list_id: Option<Uuid>,
        #[arg(long)]
        include_completed: bool,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long, hide = true)]
        raw: bool,
    },
    Get {
        #[arg(long)]
        work_list_id: Uuid,
        #[arg(long)]
        task_id: Uuid,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long, hide = true)]
        raw: bool,
    },
    Create(TaskCreateArgsCli),
    Update(TaskUpdateArgsCli),
    Move(TaskMoveArgsCli),
    Archive(TaskArchiveArgsCli),
    Unarchive(TaskUnarchiveArgsCli),
    Delete(TaskDeleteArgsCli),
    Attachments {
        #[command(subcommand)]
        command: TaskAttachmentsCommand,
    },
}

#[derive(Subcommand, Debug)]
enum TaskAttachmentsCommand {
    Read(TaskAttachmentReadArgsCli),
    Download(TaskAttachmentDownloadArgsCli),
}

#[derive(Subcommand, Debug)]
enum CommentsCommand {
    List {
        #[arg(long)]
        work_list_id: Uuid,
        #[arg(long)]
        task_id: Uuid,
        #[arg(long)]
        password_stdin: bool,
    },
    Create(CommentCreateArgsCli),
    Update(CommentUpdateArgsCli),
    Delete(CommentDeleteArgsCli),
}

#[derive(Args, Debug)]
struct TaskCreateArgsCli {
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
struct TaskUpdateArgsCli {
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
struct TaskMoveArgsCli {
    #[arg(long)]
    work_list_id: Uuid,
    #[arg(long)]
    task_id: Uuid,
    #[arg(long)]
    section_id: Option<Uuid>,
    #[arg(long)]
    insert_before_task_id: Option<Uuid>,
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Args, Debug)]
struct TaskArchiveArgsCli {
    #[arg(long)]
    work_list_id: Uuid,
    #[arg(long)]
    task_id: Uuid,
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Args, Debug)]
struct TaskUnarchiveArgsCli {
    #[arg(long)]
    work_list_id: Uuid,
    #[arg(long)]
    task_id: Uuid,
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Args, Debug)]
struct TaskDeleteArgsCli {
    #[arg(long)]
    work_list_id: Uuid,
    #[arg(long)]
    task_id: Uuid,
    #[arg(long)]
    input_file: Option<PathBuf>,
    #[arg(long)]
    input_stdin: bool,
}

#[derive(Args, Debug)]
struct CommentCreateArgsCli {
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
struct CommentUpdateArgsCli {
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

#[derive(Args, Debug)]
struct CommentDeleteArgsCli {
    #[arg(long)]
    work_list_id: Uuid,
    #[arg(long)]
    task_id: Uuid,
    #[arg(long)]
    comment_id: Uuid,
    #[arg(long)]
    input_file: Option<PathBuf>,
    #[arg(long)]
    input_stdin: bool,
}

#[derive(Args, Debug)]
struct TaskAttachmentReadArgsCli {
    #[arg(long)]
    work_list_id: Uuid,
    #[arg(long)]
    task_id: Uuid,
    #[arg(long)]
    attachment_id: Uuid,
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Args, Debug)]
struct TaskAttachmentDownloadArgsCli {
    #[arg(long)]
    work_list_id: Uuid,
    #[arg(long)]
    task_id: Uuid,
    #[arg(long)]
    attachment_id: Uuid,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    force: bool,
    #[arg(long)]
    password_stdin: bool,
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
    Login {
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        password_stdin: bool,
    },
    Unlock {
        #[arg(long, default_value_t = 8 * 60 * 60)]
        ttl_seconds: u64,
        #[arg(long)]
        password_stdin: bool,
    },
    Lock,
    Keychain {
        #[command(subcommand)]
        command: KeychainCommand,
    },
    Logout,
    Status,
}

#[derive(Subcommand, Debug)]
enum KeychainCommand {
    Store {
        #[arg(long)]
        password_stdin: bool,
    },
    Clear,
}

#[tokio::main]
async fn main() {
    let args = std::env::args_os().collect::<Vec<_>>();
    let format = OutputFormat::from_raw_args(&args);
    let cli = parse_cli_or_exit(&args, format);
    match run(cli, format).await {
        Ok(()) => {}
        Err(CliError::BrokenPipe) => std::process::exit(0),
        Err(err) => {
            let _ = print_cli_error(&err, format);
            std::process::exit(1);
        }
    }
}

fn parse_cli_or_exit(args: &[OsString], format: OutputFormat) -> Cli {
    match Cli::try_parse_from(args.iter().cloned()) {
        Ok(cli) => cli,
        Err(err) => exit_after_clap_error(err, format),
    }
}

fn exit_after_clap_error(err: clap::Error, format: OutputFormat) -> ! {
    if format == OutputFormat::Json && err.use_stderr() {
        let _ = print_clap_error(&err);
        std::process::exit(err.exit_code());
    }

    err.exit()
}

async fn run(cli: Cli, format: OutputFormat) -> CliResult<()> {
    if let Some(socket_path) = cli.serve_unlock_daemon.as_deref() {
        return serve(socket_path).await.map_err(Into::into);
    }

    let principal_selection = cli.principal.map(Into::into).unwrap_or_default();
    let runtime = RuntimeClient::with_principal_selection(&cli.api_url, principal_selection);
    let Some(command) = cli.command else {
        return Err(PublicError::validation("a command is required").into());
    };

    match command {
        Command::Info => cmd_info(&runtime),
        Command::Auth { command } => match command {
            AuthCommand::Login {
                email,
                password_stdin,
            } => cmd_login(format, runtime.api_url(), email, password_stdin).await,
            AuthCommand::Unlock {
                ttl_seconds,
                password_stdin,
            } => cmd_unlock(format, &runtime, ttl_seconds, password_stdin),
            AuthCommand::Lock => cmd_lock(format),
            AuthCommand::Keychain { command } => cmd_keychain(format, &runtime, command),
            AuthCommand::Logout => cmd_logout(format, &runtime, principal_selection).await,
            AuthCommand::Status => cmd_status(format, runtime.api_url(), principal_selection),
        },
        Command::Agent { command } => match command {
            AgentCommand::Register { proposed_handle } => {
                cmd_agent_register(format, runtime.api_url(), proposed_handle).await
            }
            AgentCommand::Approve {
                code,
                handle,
                display_name,
                password_stdin,
            } => {
                cmd_agent_approve(
                    format,
                    &runtime,
                    &code,
                    handle,
                    display_name,
                    password_stdin,
                )
                .await
            }
            AgentCommand::List => cmd_agent_list(format, &runtime).await,
            AgentCommand::Revoke { selector } => {
                cmd_agent_revoke(format, &runtime, &selector).await
            }
        },
        Command::Me => cmd_me(&runtime, format).await,
        Command::Lists {
            verbose,
            password_stdin,
            raw,
            command,
        } => match command {
            Some(ListsCommand::Get {
                work_list_id,
                password_stdin,
                raw,
            }) => cmd_lists_get(&runtime, format, work_list_id, password_stdin, raw).await,
            None => cmd_lists(&runtime, format, verbose, password_stdin, raw).await,
        },
        Command::Tasks { command } => cmd_tasks(&runtime, format, command).await,
        Command::Stats => cmd_stats(&runtime, format).await,
        Command::Inspect {
            work_list_id,
            password_stdin,
        } => cmd_lists_get(&runtime, format, work_list_id, password_stdin, false).await,
        Command::Comments { command } => cmd_comments(&runtime, format, command).await,
    }
}

fn print_cli_error(err: &CliError, format: OutputFormat) -> CliResult<()> {
    match format {
        OutputFormat::Table => {
            print_warnings(format, err.warnings())?;
            write_stderr_line(format_args!("error: {err}"))
        }
        OutputFormat::Json => print_json_stderr(
            err.warnings(),
            Some(err.error_result()),
            "serializing CLI error should succeed",
        ),
    }
}

fn print_clap_error(err: &clap::Error) -> CliResult<()> {
    print_json_error(
        "validation",
        err.to_string().trim_end().to_string(),
        "serializing clap parse error should succeed",
    )
}

fn print_json_error(code: &'static str, message: String, context: &str) -> CliResult<()> {
    print_json_stderr(&[], Some(ErrorResult { code, message }), context)
}

fn print_warnings(format: OutputFormat, warnings: &[WarningResult]) -> CliResult<()> {
    write_warnings(io::stderr().lock(), format, warnings)
}

fn emit_warnings_best_effort(format: OutputFormat, warnings: &[WarningResult]) {
    let _ = print_warnings(format, warnings);
}

#[cfg(test)]
fn emit_warnings_best_effort_to<W: Write>(
    stream: W,
    format: OutputFormat,
    warnings: &[WarningResult],
) {
    let _ = write_warnings(stream, format, warnings);
}

fn write_warnings<W: Write>(
    mut stream: W,
    format: OutputFormat,
    warnings: &[WarningResult],
) -> CliResult<()> {
    if warnings.is_empty() {
        return Ok(());
    }

    match format {
        OutputFormat::Table => {
            for warning in warnings {
                write_line_to_stream(
                    &mut stream,
                    format_args!("warning: {}", warning.message),
                    "print to",
                    "stderr",
                    false,
                )?;
            }
            Ok(())
        }
        OutputFormat::Json => {
            let output = serde_json::to_string_pretty(&StderrEnvelope {
                warnings,
                error: None,
            })
            .expect("serializing CLI warnings should succeed");
            write_line_to_stream(
                stream,
                format_args!("{output}"),
                "print to",
                "stderr",
                false,
            )
        }
    }
}

fn print_json_stderr(
    warnings: &[WarningResult],
    error: Option<ErrorResult>,
    context: &str,
) -> CliResult<()> {
    print_pretty_json_stderr(&StderrEnvelope { warnings, error }, context)
}

fn require_password_stdin_for_json_command(
    format: OutputFormat,
    password_stdin: bool,
    command_name: &str,
) -> CliResult<()> {
    if format == OutputFormat::Json && !password_stdin {
        return Err(PublicError::validation(format!(
            "--json {command_name} requires --password-stdin"
        ))
        .into());
    }

    Ok(())
}

fn cmd_info(runtime: &RuntimeClient) -> CliResult<()> {
    let payload = json!({
        "apiBaseUrl": runtime.api_url(),
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
        "decryptedReadModel": true,
        "note": "This CLI is intended for agent-friendly task and comment workflows against Worklist.",
    });
    print_pretty_json(&payload, "serializing CLI metadata should succeed")
}

async fn cmd_login(
    format: OutputFormat,
    api_url: &str,
    email_flag: Option<String>,
    password_stdin: bool,
) -> CliResult<()> {
    if let Some(credentials) = load_credentials_for_url(api_url)?
        && !credentials.is_refresh_expired()
    {
        let result = build_login_result(normalize_api_url(api_url), credentials.email, true)?;
        print_login_result(format, &result, api_url)?;
        return Ok(());
    }

    if format == OutputFormat::Json && email_flag.is_none() {
        return Err(PublicError::validation("--json auth login requires --email").into());
    }

    let email = match email_flag {
        Some(email) => email,
        None => prompt("Email: ")?,
    };
    if email.is_empty() {
        return Err(PublicError::validation("email is required").into());
    }

    require_password_stdin_for_json_command(format, password_stdin, "auth login")?;

    let password = read_required_password(password_stdin, None)?;
    if format == OutputFormat::Table {
        println!("Authenticating...");
    }
    let client = reqwest::Client::new();
    let auth_response = login(&client, api_url, &email, &password).await?;
    let credentials = auth_response_to_credentials(api_url, auth_response);
    save_credentials(&credentials)?;

    let result = build_login_result(
        credentials.api_url.clone(),
        credentials.email.clone(),
        false,
    )?;
    print_login_result(format, &result, api_url)?;
    Ok(())
}

fn cmd_unlock(
    format: OutputFormat,
    runtime: &RuntimeClient,
    ttl_seconds: u64,
    password_stdin: bool,
) -> CliResult<()> {
    require_password_stdin_for_json_command(format, password_stdin, "auth unlock")?;
    runtime.unlock_daemon(ttl_seconds, password_stdin)?;
    print_unlock_result(
        format,
        true,
        Some(ttl_seconds),
        &format!("Unlocked local daemon for {} seconds.", ttl_seconds),
    )
}

fn cmd_lock(format: OutputFormat) -> CliResult<()> {
    lock()?;
    print_unlock_result(format, false, None, "Locked local daemon.")
}

fn cmd_keychain(
    format: OutputFormat,
    runtime: &RuntimeClient,
    command: KeychainCommand,
) -> CliResult<()> {
    let (status, table_message) = match command {
        KeychainCommand::Store { password_stdin } => {
            require_password_stdin_for_json_command(format, password_stdin, "auth keychain store")?;
            runtime.store_persisted_data_key(password_stdin)?;
            (
                "available",
                "Stored a local bootstrap secret in the platform keychain.",
            )
        }
        KeychainCommand::Clear => {
            runtime.clear_persisted_data_key()?;
            (
                "cleared",
                "Cleared the local bootstrap secret from the platform keychain.",
            )
        }
    };

    print_simple_result(
        format,
        &persisted_bootstrap_envelope(status),
        "serializing keychain result should succeed",
        table_message,
    )
}

async fn cmd_logout(
    format: OutputFormat,
    runtime: &RuntimeClient,
    principal_selection: PrincipalSelection,
) -> CliResult<()> {
    let principal_credentials =
        load_principal_credentials_for_url(runtime.api_url(), principal_selection)?;
    let Some(principal_credentials) = principal_credentials else {
        return print_simple_result(
            format,
            &LogoutResult {
                logged_out: false,
                api_url: None,
                reason: Some("not_logged_in"),
            },
            "serializing logout result should succeed",
            "Not logged in.",
        );
    };

    let mut warnings = Vec::new();
    let mut cleanup_error = None;

    match principal_credentials {
        PrincipalCredentials::User(credentials) => {
            let client = reqwest::Client::new();
            if let Some(warning) = logout_revoke_warning(
                logout(&client, runtime.api_url(), &credentials.refresh_token).await,
            ) {
                warnings.push(warning);
            }

            if let Err(err) = runtime.clear_persisted_data_key() {
                warnings.push(warning_result(
                    "logout_persisted_bootstrap_clear_failed",
                    format!("failed to clear platform keychain entry: {err}"),
                ));
            }

            record_logout_cleanup_result(clear_credentials(), &mut cleanup_error);

            match runtime.current_session_key(&credentials) {
                Ok(session_key) => {
                    record_logout_cleanup_result(clear_session(&session_key), &mut cleanup_error);
                }
                Err(err) => record_logout_cleanup_result(Err(err), &mut cleanup_error),
            }
        }
        PrincipalCredentials::Agent(credentials) => {
            if let Err(err) = clear_agent_seed(&credentials) {
                warnings.push(warning_result(
                    "logout_agent_seed_clear_failed",
                    format!("failed to clear local agent seed: {err}"),
                ));
            }

            record_logout_cleanup_result(clear_agent_credentials(), &mut cleanup_error);
        }
    }

    if let Some(err) = cleanup_error {
        return Err(CliError::with_warnings(err, &warnings));
    }

    emit_warnings_best_effort(format, &warnings);
    print_simple_result(
        format,
        &LogoutResult {
            logged_out: true,
            api_url: Some(runtime.api_url().to_string()),
            reason: None,
        },
        "serializing logout result should succeed",
        "Logged out successfully.",
    )?;
    Ok(())
}

fn cmd_status(
    format: OutputFormat,
    api_url: &str,
    principal_selection: PrincipalSelection,
) -> CliResult<()> {
    match load_auth_status(api_url, principal_selection)? {
        AuthStatusResult::LoggedIn(status) => match format {
            OutputFormat::Json => {
                print_pretty_json(&status, "serializing auth status should succeed")
            }
            OutputFormat::Table => print_logged_in_auth_status(&status),
        },
        AuthStatusResult::LoggedOut(status) => match format {
            OutputFormat::Json => print_pretty_json(
                &status,
                "serializing unauthenticated auth status should succeed",
            ),
            OutputFormat::Table => print_logged_out_auth_status(&status),
        },
    }
}

fn print_simple_result<T: Serialize + ?Sized>(
    format: OutputFormat,
    payload: &T,
    context: &str,
    table_message: &str,
) -> CliResult<()> {
    match format {
        OutputFormat::Json => print_pretty_json(payload, context),
        OutputFormat::Table => {
            println!("{table_message}");
            Ok(())
        }
    }
}

fn print_unlock_result(
    format: OutputFormat,
    unlocked: bool,
    ttl_seconds: Option<u64>,
    table_message: &str,
) -> CliResult<()> {
    print_simple_result(
        format,
        &UnlockResult {
            unlocked,
            mode: "daemon",
            ttl_seconds,
        },
        "serializing unlock result should succeed",
        table_message,
    )
}

fn build_login_result(
    api_url: String,
    email: String,
    already_logged_in: bool,
) -> CliResult<LoginResult> {
    Ok(LoginResult {
        logged_in: true,
        already_logged_in,
        email,
        api_url,
        credentials_path: credentials_path_string()?,
    })
}

fn print_login_result(format: OutputFormat, result: &LoginResult, api_url: &str) -> CliResult<()> {
    match format {
        OutputFormat::Json => print_pretty_json(result, "serializing login result should succeed"),
        OutputFormat::Table => {
            if result.already_logged_in {
                println!("Already logged in as {} ({api_url})", result.email);
            } else {
                println!("Logged in as {}", result.email);
                println!("Credentials saved to {}", result.credentials_path);
            }
            Ok(())
        }
    }
}

async fn cmd_agent_register(
    format: OutputFormat,
    api_url: &str,
    proposed_handle: Option<String>,
) -> CliResult<()> {
    let current_api_url = normalize_api_url(api_url);
    ensure_agent_registration_slot_available(&current_api_url)?;

    let key_material = generate_agent_key_material()?;
    let client = reqwest::Client::new();
    let enrollment = register_agent(&client, api_url, &key_material, proposed_handle).await?;
    let credentials = AgentCredentials {
        api_url: current_api_url,
        agent_id: enrollment.agent_id,
        owner_user_id: enrollment.owner_user_id,
        handle: enrollment
            .handle
            .clone()
            .or_else(|| enrollment.proposed_handle.clone()),
        display_name: enrollment.display_name.clone(),
        access_token: None,
        access_expires_at: None,
    };
    save_agent_credentials(&credentials)?;
    if let Err(err) = save_agent_seed(&credentials, &key_material.seed) {
        let _ = clear_agent_credentials();
        return Err(err.into());
    }

    let result = AgentRegisterResult {
        registered: true,
        agent_id: enrollment.agent_id,
        enrollment_code: enrollment.enrollment_code.clone(),
        fingerprint: enrollment.fingerprint,
        api_url: credentials.api_url,
        credentials_path: agent_credentials_path()?.display().to_string(),
    };

    match format {
        OutputFormat::Json => {
            print_pretty_json(&result, "serializing agent register result should succeed")
        }
        OutputFormat::Table => {
            println!(
                "Enrollment code: {}",
                enrollment.enrollment_code.unwrap_or_else(|| "-".into())
            );
            println!("Public-key fingerprint: {}", result.fingerprint);
            println!("Agent ID: {}", result.agent_id);
            println!("Agent credentials saved to {}", result.credentials_path);
            Ok(())
        }
    }
}

fn ensure_agent_registration_slot_available(current_api_url: &str) -> CliResult<()> {
    let Some(existing_credentials) = load_agent_credentials()? else {
        return Ok(());
    };

    let message =
        agent_registration_conflict_message(&existing_credentials.api_url, current_api_url);
    Err(PublicError::validation(message).into())
}

fn agent_registration_conflict_message(existing_api_url: &str, current_api_url: &str) -> String {
    if existing_api_url == current_api_url {
        return "agent credentials already exist for this API URL".to_string();
    }

    format!(
        "agent credentials already exist for {existing_api_url}; remove that registration before registering an agent for {current_api_url}"
    )
}

async fn cmd_agent_approve(
    format: OutputFormat,
    runtime: &RuntimeClient,
    code: &str,
    handle: String,
    display_name: String,
    password_stdin: bool,
) -> CliResult<()> {
    require_password_stdin_for_json_command(format, password_stdin, "agent approve")?;
    let client = reqwest::Client::new();
    let enrollment = fetch_agent_enrollment(&client, runtime.api_url(), code).await?;
    let grants = runtime
        .build_agent_grants_for_enrollment(&enrollment, password_stdin)
        .await?;
    let mut api = runtime.authenticated_owner_api_client().await?;
    let approved = api
        .approve_agent_enrollment(&ApproveAgentEnrollmentRequest {
            code: code.to_string(),
            handle,
            display_name,
            scope_mode: "inherit_owner".to_string(),
            fingerprint: enrollment.fingerprint,
            grants,
        })
        .await?;
    print_agent_summaries(
        format,
        &[approved],
        "serializing agent approve result should succeed",
    )
}

async fn cmd_agent_list(format: OutputFormat, runtime: &RuntimeClient) -> CliResult<()> {
    let mut api = runtime.authenticated_owner_api_client().await?;
    let agents = api.list_agents().await?;
    print_agent_summaries(format, &agents, "serializing agent list should succeed")
}

async fn cmd_agent_revoke(
    format: OutputFormat,
    runtime: &RuntimeClient,
    selector: &str,
) -> CliResult<()> {
    let mut api = runtime.authenticated_owner_api_client().await?;
    let agents = api.list_agents().await?;
    let agent = agents
        .iter()
        .find(|agent| {
            agent.agent_id.to_string() == selector
                || agent
                    .handle
                    .as_deref()
                    .map(|handle| handle == selector || format!("@{handle}") == selector)
                    .unwrap_or(false)
        })
        .cloned()
        .ok_or_else(|| PublicError::validation("agent not found"))?;
    let revoked = api.revoke_agent(agent.agent_id).await?;
    print_agent_summaries(
        format,
        &[revoked],
        "serializing agent revoke result should succeed",
    )
}

fn print_agent_summaries(
    format: OutputFormat,
    agents: &[AgentSummaryResponse],
    context: &str,
) -> CliResult<()> {
    match format {
        OutputFormat::Json => print_pretty_json(agents, context),
        OutputFormat::Table => {
            if agents.is_empty() {
                println!("No agents found.");
                return Ok(());
            }
            for agent in agents {
                println!(
                    "{}  {}  {}  grants={}  last_seen={}",
                    agent.handle.as_deref().unwrap_or("-"),
                    agent.display_name.as_deref().unwrap_or("-"),
                    agent.status,
                    agent.grants.len(),
                    agent
                        .last_seen_at
                        .map(|value| value.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "-".into())
                );
            }
            Ok(())
        }
    }
}

fn credentials_path_string() -> CliResult<String> {
    Ok(credentials_path()?.display().to_string())
}

fn load_auth_status(
    api_url: &str,
    principal_selection: PrincipalSelection,
) -> CliResult<AuthStatusResult> {
    let current_api_url = normalize_api_url(api_url);
    let user_credentials = load_credentials()?;
    let agent_credentials = load_agent_credentials()?;

    match (principal_selection, user_credentials, agent_credentials) {
        (PrincipalSelection::Auto, Some(credentials), _)
        | (PrincipalSelection::User, Some(credentials), _) => {
            logged_in_auth_status(credentials, &current_api_url)
        }
        (PrincipalSelection::Auto, None, Some(credentials))
        | (PrincipalSelection::Agent, _, Some(credentials)) => {
            logged_in_agent_auth_status(credentials, &current_api_url)
        }
        (PrincipalSelection::Auto, None, None)
        | (PrincipalSelection::User, None, _)
        | (PrincipalSelection::Agent, _, None) => logged_out_auth_status(),
    }
}

fn logged_in_auth_status(
    credentials: Credentials,
    current_api_url: &str,
) -> CliResult<AuthStatusResult> {
    let session_key = current_session_key(&credentials)?;
    let unlock_status = unlock_status(Some(&session_key))?;
    let session_state = session_state(&credentials);
    let api_url_mismatch = api_url_mismatch(&credentials.api_url, current_api_url);
    let persisted_bootstrap = persisted_bootstrap_status(persisted_data_key_status(&credentials));
    let Credentials {
        api_url,
        access_token: _,
        refresh_token: _,
        access_expires_at,
        refresh_expires_at,
        user_id,
        email,
        data_key_ciphertext: _,
    } = credentials;

    Ok(AuthStatusResult::LoggedIn(Box::new(LoggedInStatusResult {
        logged_in: true,
        principal_type: "user",
        api_url,
        email: Some(email),
        user_id: Some(user_id),
        agent_id: None,
        owner_user_id: None,
        handle: None,
        display_name: None,
        access_token_expires_at: Some(access_expires_at.to_rfc3339()),
        refresh_token_expires_at: Some(refresh_expires_at.to_rfc3339()),
        access_token_expires_display: Some(
            access_expires_at
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
        ),
        refresh_token_expires_display: Some(
            refresh_expires_at
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
        ),
        session_state,
        api_url_mismatch,
        unlock_daemon: unlock_daemon_status(unlock_status),
        persisted_bootstrap,
    })))
}

fn logged_in_agent_auth_status(
    credentials: AgentCredentials,
    current_api_url: &str,
) -> CliResult<AuthStatusResult> {
    let session_state = agent_session_state(&credentials);
    let api_url_mismatch = api_url_mismatch(&credentials.api_url, current_api_url);
    let access_token_expires_at = credentials
        .access_expires_at
        .map(|value| value.to_rfc3339());
    let access_token_expires_display = credentials
        .access_expires_at
        .map(|value| value.format("%Y-%m-%d %H:%M:%S UTC").to_string());
    let AgentCredentials {
        api_url,
        agent_id,
        owner_user_id,
        handle,
        display_name,
        access_token: _,
        access_expires_at: _,
    } = credentials;

    Ok(AuthStatusResult::LoggedIn(Box::new(LoggedInStatusResult {
        logged_in: true,
        principal_type: "agent",
        api_url,
        email: None,
        user_id: None,
        agent_id: Some(agent_id),
        owner_user_id,
        handle,
        display_name,
        access_token_expires_at,
        refresh_token_expires_at: None,
        access_token_expires_display,
        refresh_token_expires_display: None,
        session_state,
        api_url_mismatch,
        unlock_daemon: inactive_unlock_daemon_status(),
        persisted_bootstrap: unavailable_persisted_bootstrap_status(),
    })))
}

fn logged_out_auth_status() -> CliResult<AuthStatusResult> {
    Ok(AuthStatusResult::LoggedOut(LoggedOutStatusResult {
        logged_in: false,
        credentials_path: credentials_path_string()?,
        unlock_daemon: inactive_unlock_daemon_status(),
        persisted_bootstrap: unavailable_persisted_bootstrap_status(),
    }))
}

fn current_session_key(credentials: &Credentials) -> CliResult<SessionKey> {
    Ok(session_key(
        &credentials.api_url,
        credentials.user_id,
        &credentials.data_key_ciphertext,
    )?)
}

fn api_url_mismatch(stored_api_url: &str, current_api_url: &str) -> Option<ApiUrlMismatch> {
    (stored_api_url != current_api_url).then(|| ApiUrlMismatch {
        stored_api_url: stored_api_url.to_string(),
        current_api_url: current_api_url.to_string(),
    })
}

fn unlock_daemon_status(status: UnlockStatus) -> UnlockDaemonStatusResult {
    UnlockDaemonStatusResult {
        active: status.unlocked,
        expires_at_unix: status.expires_at_unix,
    }
}

fn inactive_unlock_daemon_status() -> UnlockDaemonStatusResult {
    unlock_daemon_status(UnlockStatus {
        unlocked: false,
        session_key: None,
        expires_at_unix: None,
    })
}

fn persisted_bootstrap_status(status: PersistedDataKeyStatus) -> PersistedBootstrapStatus {
    match status {
        PersistedDataKeyStatus::Available => simple_persisted_bootstrap_status("available"),
        PersistedDataKeyStatus::Missing => simple_persisted_bootstrap_status("missing"),
        PersistedDataKeyStatus::Unavailable(message) => PersistedBootstrapStatus {
            status: "unavailable",
            message: Some(message),
        },
    }
}

fn simple_persisted_bootstrap_status(status: &'static str) -> PersistedBootstrapStatus {
    PersistedBootstrapStatus {
        status,
        message: None,
    }
}

fn persisted_bootstrap_envelope(status: &'static str) -> PersistedBootstrapEnvelope {
    PersistedBootstrapEnvelope {
        persisted_bootstrap: simple_persisted_bootstrap_status(status),
    }
}

fn unavailable_persisted_bootstrap_status() -> PersistedBootstrapStatus {
    PersistedBootstrapStatus {
        status: "unavailable",
        message: Some("unavailable for current target".to_string()),
    }
}

fn print_logged_in_auth_status(status: &LoggedInStatusResult) -> CliResult<()> {
    match status.principal_type {
        "user" => {
            println!(
                "Logged in as: {}",
                status.email.as_deref().unwrap_or("unknown user")
            );
            println!("API URL: {}", status.api_url);
            println!("User ID: {}", status.user_id.unwrap_or_default());
            println!(
                "Access token expires: {}",
                status
                    .access_token_expires_display
                    .as_deref()
                    .unwrap_or("-")
            );
            println!(
                "Refresh token expires: {}",
                status
                    .refresh_token_expires_display
                    .as_deref()
                    .unwrap_or("-")
            );
        }
        "agent" => {
            println!(
                "Logged in as agent: {}",
                format_agent_identity(status)
                    .as_deref()
                    .unwrap_or("unknown agent")
            );
            println!("API URL: {}", status.api_url);
            println!("Agent ID: {}", status.agent_id.unwrap_or_default());
            if let Some(owner_user_id) = status.owner_user_id {
                println!("Owner User ID: {}", owner_user_id);
            }
            if let Some(expires_at) = status.access_token_expires_display.as_deref() {
                println!("Access token expires: {expires_at}");
            }
        }
        _ => {
            println!("Logged in.");
            println!("API URL: {}", status.api_url);
        }
    }

    if let Some(mismatch) = status.api_url_mismatch.as_ref() {
        println!("\nNote: Stored credentials are for a different API URL.");
        println!("Stored: {}", mismatch.stored_api_url);
        println!("Current: {}", mismatch.current_api_url);
    }

    if let Some(notice) = session_state_notice(status.session_state) {
        println!("\n{notice}");
    }

    print_unlock_daemon_status(&status.unlock_daemon, "\n")?;
    print_persisted_bootstrap_status(&status.persisted_bootstrap)
}

fn print_logged_out_auth_status(status: &LoggedOutStatusResult) -> CliResult<()> {
    println!("Not logged in.");
    println!(
        "Credentials would be stored at: {}",
        status.credentials_path
    );
    println!("Unlock daemon: inactive for current target");
    println!("Persisted bootstrap: unavailable for current target");
    Ok(())
}

fn print_unlock_daemon_status(
    status: &UnlockDaemonStatusResult,
    line_prefix: &str,
) -> CliResult<()> {
    match (status.active, status.expires_at_unix) {
        (true, Some(expires_at_unix)) => {
            println!(
                "{line_prefix}Unlock daemon: active until unix {}",
                expires_at_unix
            )
        }
        (true, None) => println!("{line_prefix}Unlock daemon: active"),
        (false, _) => println!("{line_prefix}Unlock daemon: inactive"),
    }
    Ok(())
}

fn print_persisted_bootstrap_status(status: &PersistedBootstrapStatus) -> CliResult<()> {
    match status.message.as_deref() {
        Some(message) => println!("Persisted bootstrap: {} ({message})", status.status),
        None => println!("Persisted bootstrap: {}", status.status),
    }
    Ok(())
}

fn session_state(credentials: &Credentials) -> &'static str {
    if credentials.is_refresh_expired() {
        "refresh_expired"
    } else if credentials.is_access_expired() {
        "access_expired"
    } else {
        "active"
    }
}

fn agent_session_state(credentials: &AgentCredentials) -> &'static str {
    match credentials.access_expires_at {
        Some(_) if credentials.access_expires_within(0) => "access_expired",
        Some(_) if credentials.access_token.is_some() => "active",
        _ => "registered",
    }
}

fn session_state_notice(session_state: &str) -> Option<&'static str> {
    match session_state {
        "refresh_expired" => Some("Warning: Session has expired. Please login again."),
        "access_expired" => {
            Some("Note: Access token has expired but will be refreshed automatically.")
        }
        "registered" => Some(
            "Note: Agent credentials are registered locally and will mint access tokens automatically when needed.",
        ),
        "active" => None,
        _ => None,
    }
}

fn record_logout_cleanup_result(result: PublicResult<()>, cleanup_error: &mut Option<PublicError>) {
    if let Err(err) = result {
        cleanup_error.get_or_insert(err);
    }
}

fn format_agent_identity(status: &LoggedInStatusResult) -> Option<String> {
    match (
        status.display_name.as_deref(),
        status.handle.as_deref(),
        status.agent_id,
    ) {
        (Some(display_name), Some(handle), _) => Some(format!("{display_name} (@{handle})")),
        (Some(display_name), None, _) => Some(display_name.to_string()),
        (None, Some(handle), _) => Some(format!("@{handle}")),
        (None, None, Some(agent_id)) => Some(agent_id.to_string()),
        (None, None, None) => None,
    }
}

fn logout_revoke_warning(result: PublicResult<Option<String>>) -> Option<WarningResult> {
    match result {
        Ok(Some(message)) => Some(warning_result(
            "logout_revoke_failed",
            format!("failed to revoke token on server: {message}"),
        )),
        Ok(None) => None,
        Err(err) => Some(warning_result(
            "logout_revoke_failed",
            format!("failed to revoke token on server: {err}"),
        )),
    }
}

fn warning_result(code: &'static str, message: String) -> WarningResult {
    WarningResult { code, message }
}

async fn cmd_me(runtime: &RuntimeClient, format: OutputFormat) -> CliResult<()> {
    let user = runtime.get_me().await?;
    print_user(&user, format)?;
    Ok(())
}

async fn cmd_lists(
    runtime: &RuntimeClient,
    format: OutputFormat,
    verbose: bool,
    password_stdin: bool,
    raw: bool,
) -> CliResult<()> {
    if raw {
        let mut client = runtime.authenticated_api_client().await?;
        let lists = client.list_work_lists().await?;
        if lists.is_empty() {
            println!("No work lists found.");
            return Ok(());
        }
        print_raw_work_lists(&lists, format, verbose)?;
        return Ok(());
    }

    let lists = runtime.list_work_lists(password_stdin).await?;
    if lists.is_empty() {
        println!("No work lists found.");
        return Ok(());
    }
    print_work_lists(&lists, format, verbose)?;
    Ok(())
}

async fn cmd_lists_get(
    runtime: &RuntimeClient,
    format: OutputFormat,
    work_list_id: Uuid,
    password_stdin: bool,
    raw: bool,
) -> CliResult<()> {
    if raw {
        let mut client = runtime.authenticated_api_client().await?;
        let detail = client.get_work_list(work_list_id).await?;
        print_raw_work_list_detail(&detail, format)?;
        return Ok(());
    }

    let detail = runtime.get_work_list(work_list_id, password_stdin).await?;
    print_work_list_detail(&detail, format)?;
    Ok(())
}

async fn cmd_tasks(
    runtime: &RuntimeClient,
    format: OutputFormat,
    command: TasksCommand,
) -> CliResult<()> {
    match command {
        TasksCommand::List {
            work_list_id,
            include_completed,
            all,
            password_stdin,
            raw,
        } => {
            if raw {
                let mut client = runtime.authenticated_api_client().await?;
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
                    print_raw_my_tasks(&tasks, format)?;
                    return Ok(());
                }

                let work_list_id = work_list_id.expect("validated work list id");
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
                print_raw_tasks(&tasks, format)?;
                return Ok(());
            }

            let tasks = runtime
                .list_tasks(work_list_id, include_completed, all, password_stdin)
                .await?;
            if tasks.is_empty() {
                if all || work_list_id.is_none() {
                    println!("No tasks found.");
                } else {
                    println!("No tasks found in this work list.");
                }
                return Ok(());
            }
            print_tasks(&tasks, format)?;
            Ok(())
        }
        TasksCommand::Get {
            work_list_id,
            task_id,
            password_stdin,
            raw,
        } => {
            if raw {
                let mut client = runtime.authenticated_api_client().await?;
                let detail = client.get_task(work_list_id, task_id).await?;
                print_raw_task_detail(&detail, format)?;
                return Ok(());
            }

            let detail = runtime
                .get_task(work_list_id, task_id, password_stdin)
                .await?;
            print_task_detail(&detail, format)?;
            Ok(())
        }
        TasksCommand::Create(args) => cmd_tasks_create(runtime, args).await,
        TasksCommand::Update(args) => cmd_tasks_update(runtime, args).await,
        TasksCommand::Move(args) => cmd_tasks_move(runtime, args).await,
        TasksCommand::Archive(args) => cmd_tasks_archive(runtime, args).await,
        TasksCommand::Unarchive(args) => cmd_tasks_unarchive(runtime, args).await,
        TasksCommand::Delete(args) => cmd_tasks_delete(runtime, format, args).await,
        TasksCommand::Attachments { command } => {
            cmd_task_attachments(runtime, format, command).await
        }
    }
}

async fn cmd_task_attachments(
    runtime: &RuntimeClient,
    format: OutputFormat,
    command: TaskAttachmentsCommand,
) -> CliResult<()> {
    match command {
        TaskAttachmentsCommand::Read(args) => {
            let attachment = runtime
                .read_task_attachment(
                    args.work_list_id,
                    args.task_id,
                    args.attachment_id,
                    args.password_stdin,
                )
                .await?;
            print_readable_attachment(&attachment, format)?;
            Ok(())
        }
        TaskAttachmentsCommand::Download(args) => {
            let attachment = runtime
                .download_task_attachment(
                    args.work_list_id,
                    args.task_id,
                    args.attachment_id,
                    args.password_stdin,
                )
                .await?;
            let output_path =
                resolve_attachment_output_path(&attachment.attachment.file_name, args.output);
            write_attachment_file(&output_path, &attachment.bytes, args.force)?;
            print_download_result(format, &attachment.attachment.file_name, &output_path)?;
            Ok(())
        }
    }
}

async fn cmd_tasks_create(runtime: &RuntimeClient, args: TaskCreateArgsCli) -> CliResult<()> {
    let input = resolve_task_create_input(&args)?;
    let created = runtime
        .create_task(CreateTaskArgs {
            work_list_id: args.work_list_id,
            input,
            password_stdin: args.password_stdin,
        })
        .await?;
    print_pretty_json(&created, "serializing created task should succeed")
}

async fn cmd_tasks_update(runtime: &RuntimeClient, args: TaskUpdateArgsCli) -> CliResult<()> {
    let input = resolve_task_update_input(&args)?;
    let updated = runtime
        .update_task(UpdateTaskArgs {
            work_list_id: args.work_list_id,
            task_id: args.task_id,
            input,
            password_stdin: args.password_stdin,
        })
        .await?;
    print_pretty_json(&updated, "serializing updated task should succeed")
}

async fn cmd_tasks_move(runtime: &RuntimeClient, args: TaskMoveArgsCli) -> CliResult<()> {
    let moved = runtime
        .move_task(MoveTaskArgs {
            work_list_id: args.work_list_id,
            task_id: args.task_id,
            input: MoveTaskInput {
                section_id: args.section_id,
                insert_before_task_id: args.insert_before_task_id,
            },
            password_stdin: args.password_stdin,
        })
        .await?;
    print_pretty_json(&moved, "serializing moved task should succeed")
}

async fn cmd_tasks_archive(runtime: &RuntimeClient, args: TaskArchiveArgsCli) -> CliResult<()> {
    let archived = runtime
        .archive_task(ArchiveTaskArgs {
            work_list_id: args.work_list_id,
            task_id: args.task_id,
            password_stdin: args.password_stdin,
        })
        .await?;
    print_pretty_json(&archived, "serializing archived task should succeed")
}

async fn cmd_tasks_unarchive(runtime: &RuntimeClient, args: TaskUnarchiveArgsCli) -> CliResult<()> {
    let unarchived = runtime
        .unarchive_task(UnarchiveTaskArgs {
            work_list_id: args.work_list_id,
            task_id: args.task_id,
            password_stdin: args.password_stdin,
        })
        .await?;
    print_pretty_json(&unarchived, "serializing unarchived task should succeed")
}

async fn cmd_tasks_delete(
    runtime: &RuntimeClient,
    format: OutputFormat,
    args: TaskDeleteArgsCli,
) -> CliResult<()> {
    let input =
        resolve_delete_input::<DeleteTaskRequest>(args.input_file.as_deref(), args.input_stdin)?;
    runtime
        .delete_task(DeleteTaskArgs {
            work_list_id: args.work_list_id,
            task_id: args.task_id,
            input,
        })
        .await?;
    print_delete_result(
        format,
        "task",
        &json!({
            "deleted": true,
            "workListId": args.work_list_id,
            "taskId": args.task_id,
        }),
        &format!("Deleted task {}.", args.task_id),
    )
}

async fn cmd_stats(runtime: &RuntimeClient, format: OutputFormat) -> CliResult<()> {
    let stats = runtime.get_stats().await?;
    print_stats(&stats, format)?;
    Ok(())
}

async fn cmd_comments(
    runtime: &RuntimeClient,
    format: OutputFormat,
    command: CommentsCommand,
) -> CliResult<()> {
    match command {
        CommentsCommand::List {
            work_list_id,
            task_id,
            password_stdin,
        } => cmd_comments_list(runtime, format, work_list_id, task_id, password_stdin).await,
        CommentsCommand::Create(args) => cmd_comments_create(runtime, args).await,
        CommentsCommand::Update(args) => cmd_comments_update(runtime, args).await,
        CommentsCommand::Delete(args) => cmd_comments_delete(runtime, format, args).await,
    }
}

async fn cmd_comments_list(
    runtime: &RuntimeClient,
    format: OutputFormat,
    work_list_id: Uuid,
    task_id: Uuid,
    password_stdin: bool,
) -> CliResult<()> {
    let comments = runtime
        .list_comments(work_list_id, task_id, password_stdin)
        .await?;
    if comments.is_empty() {
        match format {
            OutputFormat::Json => {
                print_pretty_json(&comments, "serializing comments should succeed")?;
            }
            OutputFormat::Table => {
                println!("No comments found.");
            }
        }
        return Ok(());
    }
    print_comments(&comments, format)
}

async fn cmd_comments_create(runtime: &RuntimeClient, args: CommentCreateArgsCli) -> CliResult<()> {
    let input = resolve_comment_input(
        args.body.as_deref(),
        args.input_file.as_deref(),
        args.input_stdin,
        args.password_stdin,
    )?;
    let created = runtime
        .create_comment(CreateCommentArgs {
            work_list_id: args.work_list_id,
            task_id: args.task_id,
            input,
            password_stdin: args.password_stdin,
        })
        .await?;
    print_comment_json(&created)?;
    Ok(())
}

async fn cmd_comments_update(runtime: &RuntimeClient, args: CommentUpdateArgsCli) -> CliResult<()> {
    let input = resolve_comment_input(
        args.body.as_deref(),
        args.input_file.as_deref(),
        args.input_stdin,
        args.password_stdin,
    )?;
    let updated = runtime
        .update_comment(UpdateCommentArgs {
            work_list_id: args.work_list_id,
            task_id: args.task_id,
            comment_id: args.comment_id,
            input,
            password_stdin: args.password_stdin,
        })
        .await?;
    print_comment_json(&updated)?;
    Ok(())
}

async fn cmd_comments_delete(
    runtime: &RuntimeClient,
    format: OutputFormat,
    args: CommentDeleteArgsCli,
) -> CliResult<()> {
    let input =
        resolve_delete_input::<DeleteCommentRequest>(args.input_file.as_deref(), args.input_stdin)?;
    runtime
        .delete_comment(DeleteCommentArgs {
            work_list_id: args.work_list_id,
            task_id: args.task_id,
            comment_id: args.comment_id,
            input,
        })
        .await?;
    print_delete_result(
        format,
        "comment",
        &json!({
            "deleted": true,
            "workListId": args.work_list_id,
            "taskId": args.task_id,
            "commentId": args.comment_id,
        }),
        &format!("Deleted comment {}.", args.comment_id),
    )
}

fn resolve_task_create_input(args: &TaskCreateArgsCli) -> PublicResult<TaskCreateInput> {
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
        .ok_or_else(|| PublicError::validation("title is required"))?;
    Ok(TaskCreateInput {
        title,
        body: args.body.as_deref().map(str::to_owned),
    })
}

fn resolve_task_update_input(args: &TaskUpdateArgsCli) -> PublicResult<TaskUpdateInput> {
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
        .ok_or_else(|| PublicError::validation("comment body is required"))?;
    Ok(CommentInput { body })
}

fn resolve_delete_input<T: Default + DeserializeOwned>(
    input_file: Option<&Path>,
    input_stdin: bool,
) -> PublicResult<T> {
    load_structured_input(input_file, input_stdin, false).map(|input| input.unwrap_or_default())
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
        return Err(PublicError::validation(
            "use only one of --input-file or --input-stdin",
        ));
    }
    if input_stdin && password_stdin {
        return Err(PublicError::validation(
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
            PublicError::unexpected(format!(
                "failed to read input file {}: {err}",
                path.display()
            ))
        }),
        JsonInputSource::Stdin => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input).map_err(|err| {
                PublicError::unexpected(format!("failed to read input from stdin: {err}"))
            })?;
            Ok(input)
        }
    }
}

fn parse_json_input<T: DeserializeOwned>(contents: &str, source: &str) -> PublicResult<T> {
    serde_json::from_str(contents)
        .map_err(|err| PublicError::validation(format!("invalid JSON input from {source}: {err}")))
}

fn prompt(label: &str) -> CliResult<String> {
    print!("{label}");
    flush_stdout()?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|err| PublicError::unexpected(format!("failed to read input: {err}")))?;

    Ok(input.trim().to_string())
}

fn read_password_from_stdin() -> PublicResult<String> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).map_err(|err| {
        PublicError::unexpected(format!("failed to read password from stdin: {err}"))
    })?;
    Ok(input.trim().to_string())
}

fn read_required_password(password_stdin: bool, prompt_message: Option<&str>) -> CliResult<String> {
    let password = if password_stdin {
        read_password_from_stdin()?
    } else {
        if let Some(prompt_message) = prompt_message {
            println!("{prompt_message}");
        }
        rpassword::prompt_password("Password: ")
            .map_err(|err| PublicError::unexpected(format!("failed to read password: {err}")))?
    };

    if password.is_empty() {
        return Err(PublicError::validation("password is required").into());
    }
    Ok(password)
}

fn resolve_attachment_output_path(file_name: &str, output: Option<PathBuf>) -> PathBuf {
    output.unwrap_or_else(|| PathBuf::from(sanitize_attachment_file_name(file_name)))
}

fn sanitize_attachment_file_name(file_name: &str) -> String {
    let candidate = Path::new(file_name)
        .file_name()
        .and_then(|value| value.to_str())
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "." && *value != "..")
        .unwrap_or("attachment.bin");

    candidate
        .chars()
        .map(sanitize_attachment_file_name_char)
        .collect()
}

fn sanitize_attachment_file_name_char(ch: char) -> char {
    match ch {
        '/' | '\\' | '\0' => '_',
        _ => ch,
    }
}

fn write_attachment_file(path: &Path, bytes: &[u8], force: bool) -> PublicResult<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|err| {
            PublicError::unexpected(format!(
                "failed to create output directory {}: {err}",
                parent.display()
            ))
        })?;
    }

    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    let mut file = options.open(path).map_err(|err| {
        if err.kind() == io::ErrorKind::AlreadyExists {
            return PublicError::validation(format!(
                "output file {} already exists; use --force to overwrite",
                path.display()
            ));
        }
        PublicError::unexpected(format!(
            "failed to open output file {}: {err}",
            path.display()
        ))
    })?;
    file.write_all(bytes).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to write output file {}: {err}",
            path.display()
        ))
    })
}

fn print_download_result(
    format: OutputFormat,
    file_name: &str,
    output_path: &Path,
) -> CliResult<()> {
    match format {
        OutputFormat::Json => print_pretty_json(
            &json!({
                "fileName": file_name,
                "outputPath": output_path.display().to_string(),
            }),
            "serializing download result should succeed",
        )?,
        OutputFormat::Table => {
            println!("Saved attachment to {}", output_path.display());
        }
    }
    Ok(())
}

fn print_readable_attachment(
    attachment: &ReadableAttachment,
    format: OutputFormat,
) -> CliResult<()> {
    match format {
        OutputFormat::Json => {
            print_pretty_json(attachment, "serializing readable attachment should succeed")?;
        }
        OutputFormat::Table => {
            print!("{}", attachment.text);
            if !attachment.text.ends_with('\n') {
                println!();
            }
        }
    }
    Ok(())
}

fn print_comment_json(comment: &AgentComment) -> CliResult<()> {
    print_pretty_json(comment, "serializing comment should succeed")
}

fn print_comments(comments: &[AgentComment], format: OutputFormat) -> CliResult<()> {
    match format {
        OutputFormat::Json => {
            print_pretty_json(comments, "serializing comments should succeed")?;
        }
        OutputFormat::Table => {
            println!("{:<36}  {:<16}  Comment", "ID", "Updated");
            println!("{}", "-".repeat(96));
            for comment in comments {
                println!(
                    "{:<36}  {:<16}  {}",
                    comment.id,
                    comment.updated_at.format("%Y-%m-%d %H:%M"),
                    truncate(
                        comment
                            .body_markdown
                            .as_deref()
                            .unwrap_or("<unreadable comment>"),
                        40
                    )
                );
            }
            println!("\nTotal: {} comment(s)", comments.len());
        }
    }
    Ok(())
}

fn print_delete_result(
    format: OutputFormat,
    entity: &str,
    payload: &serde_json::Value,
    table_message: &str,
) -> CliResult<()> {
    match format {
        OutputFormat::Json => {
            print_pretty_json(
                payload,
                &format!("serializing deleted {entity} should succeed"),
            )?;
        }
        OutputFormat::Table => {
            println!("{table_message}");
        }
    }
    Ok(())
}

fn print_user(user: &CurrentUserResponse, format: OutputFormat) -> CliResult<()> {
    match format {
        OutputFormat::Json => print_pretty_json(user, "serializing user should succeed")?,
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
    Ok(())
}

fn print_work_lists(
    lists: &[AgentWorkListSummary],
    format: OutputFormat,
    verbose: bool,
) -> CliResult<()> {
    match format {
        OutputFormat::Json => {
            print_pretty_json(lists, "serializing work lists should succeed")?;
        }
        OutputFormat::Table => {
            if verbose {
                for (index, list) in lists.iter().enumerate() {
                    if index > 0 {
                        println!();
                    }
                    println!("Work List: {}", list.id);
                    println!("{}", "-".repeat(50));
                    println!("  Title:         {}", list.title.as_deref().unwrap_or("-"));
                    println!("  Workspace:     {}", list.workspace_id);
                    println!("  Owner:         {}", list.owner_user_id);
                    println!("  Timezone:      {}", list.timezone);
                    println!("  Sections:      {}", list.section_snapshots.len());
                    println!("  Your role:     {}", list.membership.role);
                    println!("  Your status:   {}", list.membership.status);
                    if let Some(read_error) = list.read_error.as_ref() {
                        println!("  Read error:    {}", read_error.message);
                    }
                    println!(
                        "  Updated:       {}",
                        list.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                }
                println!("\nTotal: {} work list(s)", lists.len());
            } else {
                println!("{:<36}  {:<24}  {:<10}  Updated", "ID", "Title", "Role");
                println!("{}", "-".repeat(92));
                for list in lists {
                    println!(
                        "{:<36}  {:<24}  {:<10}  {}",
                        list.id,
                        truncate(list.title.as_deref().unwrap_or("-"), 24),
                        list.membership.role,
                        list.updated_at.format("%Y-%m-%d %H:%M")
                    );
                }
                println!("\nTotal: {} work list(s)", lists.len());
            }
        }
    }
    Ok(())
}

fn print_work_list_detail(detail: &AgentWorkListDetail, format: OutputFormat) -> CliResult<()> {
    match format {
        OutputFormat::Json => {
            print_pretty_json(detail, "serializing work list detail should succeed")?;
        }
        OutputFormat::Table => {
            println!("Work List");
            println!("{}", "=".repeat(60));
            println!("ID:          {}", detail.work_list.id);
            println!(
                "Title:       {}",
                detail.work_list.title.as_deref().unwrap_or("-")
            );
            println!("Workspace:   {}", detail.work_list.workspace_id);
            println!("Owner:       {}", detail.work_list.owner_user_id);
            println!("Timezone:    {}", detail.work_list.timezone);
            println!("Members:     {}", detail.members.len());
            println!("Your role:   {}", detail.work_list.membership.role);
            println!("Your status: {}", detail.work_list.membership.status);
            if let Some(description) = detail.work_list.description.as_deref() {
                println!("Description: {}", description);
            }
            if let Some(read_error) = detail.work_list.read_error.as_ref() {
                println!("Read error:  {}", read_error.message);
            }
        }
    }
    Ok(())
}

fn print_tasks(tasks: &[AgentTaskSummary], format: OutputFormat) -> CliResult<()> {
    match format {
        OutputFormat::Json => {
            print_pretty_json(tasks, "serializing tasks should succeed")?;
        }
        OutputFormat::Table => {
            println!(
                "{:<36}  {:<40}  {:<3}  {:<10}  Status",
                "ID", "Title", "Pri", "Due"
            );
            println!("{}", "-".repeat(108));
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
                    "{:<36}  {:<40}  {:<3}  {:<10}  {}",
                    task.id,
                    truncate(task.title.as_deref().unwrap_or("-"), 40),
                    priority,
                    due,
                    status
                );
            }
            println!("\nTotal: {} task(s)", tasks.len());
        }
    }
    Ok(())
}

fn print_task_detail(detail: &AgentTaskDetail, format: OutputFormat) -> CliResult<()> {
    match format {
        OutputFormat::Json => {
            print_pretty_json(detail, "serializing task detail should succeed")?;
        }
        OutputFormat::Table => {
            let task = &detail.task;
            println!("Task");
            println!("{}", "=".repeat(60));
            println!("ID:          {}", task.id);
            println!("Title:       {}", task.title.as_deref().unwrap_or("-"));
            println!("Work List:   {}", task.work_list_id);
            if let Some(work_list_title) = task.work_list_title.as_deref() {
                println!("List Title:  {}", work_list_title);
            }
            println!(
                "Status:      {}",
                if task.is_completed { "Done" } else { "Active" }
            );
            if let Some(body) = task.body_markdown.as_deref() {
                println!();
                println!("Body");
                println!("{}", "-".repeat(60));
                println!("{body}");
            }
            if let Some(read_error) = task.read_error.as_ref() {
                println!();
                println!("Read error: {}", read_error.message);
            }
            if let Some(attachments) = task.attachments.as_ref()
                && !attachments.is_empty()
            {
                println!();
                println!("Attachments");
                println!("{}", "-".repeat(60));
                println!("{:<36}  {:<24}  Type / Size", "ID", "File");
                println!("{}", "-".repeat(96));
                for attachment in attachments {
                    println!(
                        "{:<36}  {:<24}  {} / {} B",
                        attachment.id,
                        truncate(&attachment.file_name, 24),
                        attachment.content_type,
                        attachment.size_bytes
                    );
                }
            }
            if !detail.comments.is_empty() {
                println!();
                println!("Comments");
                println!("{}", "-".repeat(60));
                for comment in &detail.comments {
                    println!(
                        "- {}",
                        comment
                            .body_markdown
                            .as_deref()
                            .unwrap_or("<unreadable comment>")
                    );
                }
            }
        }
    }
    Ok(())
}

fn print_stats(stats: &DashboardStatsResponse, format: OutputFormat) -> CliResult<()> {
    match format {
        OutputFormat::Json => {
            print_pretty_json(stats, "serializing stats should succeed")?;
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
    Ok(())
}

fn print_raw_work_lists(
    lists: &[WorkListResponse],
    format: OutputFormat,
    verbose: bool,
) -> CliResult<()> {
    match format {
        OutputFormat::Json => {
            print_pretty_json(lists, "serializing work lists should succeed")?;
        }
        OutputFormat::Table => {
            if verbose {
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
                }
                println!("\nTotal: {} work list(s)", lists.len());
            } else {
                println!("{:<36}  {:<10}  {:<8}  Updated", "ID", "Role", "Sections");
                println!("{}", "-".repeat(80));
                for list in lists {
                    println!(
                        "{:<36}  {:<10}  {:<8}  {}",
                        list.id,
                        list.membership.role,
                        list.section_snapshots.len(),
                        list.updated_at.format("%Y-%m-%d %H:%M")
                    );
                }
                println!("\nTotal: {} work list(s)", lists.len());
            }
        }
    }
    Ok(())
}

fn print_raw_work_list_detail(
    detail: &WorkListDetailResponse,
    format: OutputFormat,
) -> CliResult<()> {
    match format {
        OutputFormat::Json => {
            print_pretty_json(detail, "serializing raw work list detail should succeed")?;
        }
        OutputFormat::Table => {
            println!("Raw Work List");
            println!("{}", "=".repeat(60));
            println!("ID:          {}", detail.work_list.id);
            println!("Workspace:   {}", detail.work_list.workspace_id);
            println!("Owner:       {}", detail.work_list.owner_user_id);
            println!("Members:     {}", detail.members.len());
        }
    }
    Ok(())
}

fn print_raw_tasks(tasks: &[TaskResponse], format: OutputFormat) -> CliResult<()> {
    match format {
        OutputFormat::Json => {
            print_pretty_json(tasks, "serializing tasks should succeed")?;
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
    Ok(())
}

fn print_raw_my_tasks(
    tasks: &[worklist_client_api::MyTaskResponse],
    format: OutputFormat,
) -> CliResult<()> {
    match format {
        OutputFormat::Json => {
            print_pretty_json(tasks, "serializing my tasks should succeed")?;
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
    Ok(())
}

fn print_raw_task_detail(detail: &TaskDetailResponse, format: OutputFormat) -> CliResult<()> {
    match format {
        OutputFormat::Json => {
            print_pretty_json(detail, "serializing raw task detail should succeed")?;
        }
        OutputFormat::Table => {
            println!("Raw Task");
            println!("{}", "=".repeat(60));
            println!("ID:          {}", detail.task.id);
            println!("Work List:   {}", detail.task.work_list_id);
            println!("Comments:    {}", detail.comments.len());
        }
    }
    Ok(())
}

fn truncate(value: &str, width: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(width).collect();
    if chars.next().is_some() {
        truncated
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysFailWriter;

    impl Write for AlwaysFailWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "stderr closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn broken_pipe_stdout_errors_are_classified_separately() {
        let error = io::Error::new(io::ErrorKind::BrokenPipe, "stdout closed");
        assert!(matches!(
            map_stream_error(error, "print to", "stdout", true),
            CliError::BrokenPipe
        ));
    }

    #[test]
    fn non_broken_pipe_stdout_errors_become_public_errors() {
        let error = io::Error::other("disk exploded");
        assert!(matches!(
            map_stream_error(error, "print to", "stdout", true),
            CliError::Public(PublicError::Unexpected(message))
                if message.contains("failed to print to stdout: disk exploded")
        ));
    }

    #[test]
    fn broken_pipe_stderr_errors_remain_failures() {
        let error = io::Error::new(io::ErrorKind::BrokenPipe, "stderr closed");
        assert!(matches!(
            map_stream_error(error, "print to", "stderr", false),
            CliError::Public(PublicError::Unexpected(message))
                if message.contains("failed to print to stderr: stderr closed")
        ));
    }

    #[test]
    fn best_effort_warning_emission_ignores_stderr_failures() {
        let warnings = [warning_result(
            "logout_revoke_failed",
            "failed to revoke token on server: stderr closed".to_string(),
        )];

        assert!(write_warnings(AlwaysFailWriter, OutputFormat::Json, &warnings).is_err());
        emit_warnings_best_effort_to(AlwaysFailWriter, OutputFormat::Json, &warnings);
    }
}
