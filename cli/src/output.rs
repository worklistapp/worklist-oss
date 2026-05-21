use worklist_client_api::{
    CurrentUserResponse, DashboardStatsResponse, TaskDetailResponse, TaskResponse,
    WorkListDetailResponse, WorkListResponse,
};
use worklist_client_runtime::{
    AgentComment, AgentTaskDetail, AgentTaskSummary, AgentWorkListDetail, AgentWorkListSummary,
    ReadableAttachment,
};

use super::{CliResult, OutputFormat, print_pretty_json};

pub(super) fn print_readable_attachment(
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

pub(super) fn print_comment_json(comment: &AgentComment) -> CliResult<()> {
    print_pretty_json(comment, "serializing comment should succeed")
}

pub(super) fn print_comments(comments: &[AgentComment], format: OutputFormat) -> CliResult<()> {
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

pub(super) fn print_delete_result(
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

pub(super) fn print_user(user: &CurrentUserResponse, format: OutputFormat) -> CliResult<()> {
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

pub(super) fn print_work_lists(
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

pub(super) fn print_work_list_detail(
    detail: &AgentWorkListDetail,
    format: OutputFormat,
) -> CliResult<()> {
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

pub(super) fn print_tasks(tasks: &[AgentTaskSummary], format: OutputFormat) -> CliResult<()> {
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

pub(super) fn print_task_detail(detail: &AgentTaskDetail, format: OutputFormat) -> CliResult<()> {
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

pub(super) fn print_stats(stats: &DashboardStatsResponse, format: OutputFormat) -> CliResult<()> {
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

pub(super) fn print_raw_work_lists(
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

pub(super) fn print_raw_work_list_detail(
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

pub(super) fn print_raw_tasks(tasks: &[TaskResponse], format: OutputFormat) -> CliResult<()> {
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

pub(super) fn print_raw_my_tasks(
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

pub(super) fn print_raw_task_detail(
    detail: &TaskDetailResponse,
    format: OutputFormat,
) -> CliResult<()> {
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
