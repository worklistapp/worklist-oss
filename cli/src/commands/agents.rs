use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use clap::Subcommand;
use serde::Serialize;
use uuid::Uuid;
use worklist_client_api::{AgentSummaryResponse, ApproveAgentEnrollmentRequest};
use worklist_client_auth::{
    AgentCredentials, agent_credentials_path, clear_agent_credentials, fetch_agent_enrollment,
    generate_agent_key_material, load_agent_credentials, normalize_api_url, register_agent,
    save_agent_credentials, save_agent_seed,
};
use worklist_client_core::PublicError;
use worklist_client_runtime::RuntimeClient;

use crate::{
    CliError, CliResult, OutputFormat, print_pretty_json, println_stdout,
    require_password_stdin_for_json_command, warning_result,
};

#[derive(Debug, Subcommand)]
pub(crate) enum AgentCommand {
    Register {
        #[arg(long)]
        proposed_handle: Option<String>,
    },
    Approve {
        #[arg(value_name = "CODE", hide = true)]
        deprecated_code: Option<String>,
        #[arg(long, conflicts_with_all = ["code_file", "password_stdin"])]
        code_stdin: bool,
        #[arg(long, value_name = "PATH", conflicts_with = "code_stdin")]
        code_file: Option<PathBuf>,
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

pub(crate) struct AgentApproveArgs<'a> {
    pub(crate) format: OutputFormat,
    pub(crate) runtime: &'a RuntimeClient,
    pub(crate) deprecated_code: Option<&'a str>,
    pub(crate) code_stdin: bool,
    pub(crate) code_file: Option<&'a Path>,
    pub(crate) handle: String,
    pub(crate) display_name: String,
    pub(crate) password_stdin: bool,
}

pub(crate) async fn cmd_agent_register(
    format: OutputFormat,
    api_url: &str,
    proposed_handle: Option<String>,
) -> CliResult<()> {
    let current_api_url = normalize_api_url(api_url);
    ensure_agent_registration_slot_available(&current_api_url)?;

    let key_material = generate_agent_key_material()?;
    let client = reqwest::Client::new();
    let enrollment = register_agent(&client, api_url, &key_material, proposed_handle).await?;
    let credentials = AgentCredentials::registered(
        current_api_url,
        enrollment.agent_id,
        enrollment.owner_user_id,
        enrollment
            .handle
            .clone()
            .or_else(|| enrollment.proposed_handle.clone()),
        enrollment.display_name.clone(),
    );
    save_agent_credentials(&credentials)?;
    if let Err(err) = save_agent_seed(&credentials, key_material.seed()) {
        return match clear_agent_credentials() {
            Ok(()) => Err(err.into()),
            Err(cleanup_err) => {
                let warning = warning_result(
                    "agent_registration_cleanup_failed",
                    format!("failed to remove partial agent credentials: {cleanup_err}"),
                );
                Err(CliError::with_warnings(err, &[warning]))
            }
        };
    }

    let result = AgentRegisterResult {
        registered: true,
        agent_id: enrollment.agent_id,
        enrollment_code: enrollment.enrollment_code.clone(),
        fingerprint: enrollment.fingerprint,
        api_url: credentials.api_url().to_string(),
        credentials_path: agent_credentials_path()?.display().to_string(),
    };

    match format {
        OutputFormat::Json => {
            print_pretty_json(&result, "serializing agent register result should succeed")
        }
        OutputFormat::Table => {
            println_stdout(format_args!(
                "Enrollment code: {}",
                enrollment.enrollment_code.unwrap_or_else(|| "-".into())
            ))?;
            println_stdout(format_args!(
                "Public-key fingerprint: {}",
                result.fingerprint
            ))?;
            println_stdout(format_args!("Agent ID: {}", result.agent_id))?;
            println_stdout(format_args!(
                "Agent credentials saved to {}",
                result.credentials_path
            ))?;
            Ok(())
        }
    }
}

fn ensure_agent_registration_slot_available(current_api_url: &str) -> CliResult<()> {
    let Some(existing_credentials) = load_agent_credentials()? else {
        return Ok(());
    };

    let message =
        agent_registration_conflict_message(existing_credentials.api_url(), current_api_url);
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

pub(crate) async fn cmd_agent_approve(args: AgentApproveArgs<'_>) -> CliResult<()> {
    let AgentApproveArgs {
        format,
        runtime,
        deprecated_code,
        code_stdin,
        code_file,
        handle,
        display_name,
        password_stdin,
    } = args;
    require_password_stdin_for_json_command(format, password_stdin, "agent approve")?;
    let code = read_agent_enrollment_code(deprecated_code, code_stdin, code_file)?;
    let client = reqwest::Client::new();
    let enrollment = fetch_agent_enrollment(&client, runtime.api_url(), &code).await?;
    let grants = runtime
        .build_agent_grants_for_enrollment(&enrollment, password_stdin)
        .await?;
    let mut api = runtime.authenticated_owner_api_client().await?;
    let approved = api
        .approve_agent_enrollment(&ApproveAgentEnrollmentRequest {
            code,
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

fn read_agent_enrollment_code(
    deprecated_code: Option<&str>,
    code_stdin: bool,
    code_file: Option<&Path>,
) -> CliResult<String> {
    let raw = match (deprecated_code, code_stdin, code_file) {
        (None, true, None) => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input).map_err(|err| {
                PublicError::unexpected(format!(
                    "failed to read agent enrollment code from stdin: {err}"
                ))
            })?;
            input
        }
        (None, false, Some(path)) => fs::read_to_string(path).map_err(|err| {
            PublicError::unexpected(format!(
                "failed to read agent enrollment code file {}: {err}",
                path.display()
            ))
        })?,
        (Some(_), _, _) => {
            return Err(PublicError::validation(
                "agent approve no longer accepts the enrollment code as a positional argument; use --code-stdin or --code-file to avoid shell history and process-list exposure",
            )
            .into());
        }
        (None, false, None) => {
            return Err(PublicError::validation(
                "agent approve requires --code-stdin or --code-file",
            )
            .into());
        }
        (None, true, Some(_)) => unreachable!("clap enforces code source conflicts"),
    };
    let code = raw.trim().to_string();
    if code.is_empty() {
        return Err(PublicError::validation("agent enrollment code cannot be empty").into());
    }
    Ok(code)
}

pub(crate) async fn cmd_agent_list(format: OutputFormat, runtime: &RuntimeClient) -> CliResult<()> {
    let mut api = runtime.authenticated_owner_api_client().await?;
    let agents = api.list_agents().await?;
    print_agent_summaries(format, &agents, "serializing agent list should succeed")
}

pub(crate) async fn cmd_agent_revoke(
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
                println_stdout(format_args!("No agents found."))?;
                return Ok(());
            }
            for agent in agents {
                println_stdout(format_args!(
                    "{}  {}  {}  grants={}  last_seen={}",
                    agent.handle.as_deref().unwrap_or("-"),
                    agent.display_name.as_deref().unwrap_or("-"),
                    agent.status,
                    agent.grants.len(),
                    agent
                        .last_seen_at
                        .map(|value| value.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "-".into())
                ))?;
            }
            Ok(())
        }
    }
}
