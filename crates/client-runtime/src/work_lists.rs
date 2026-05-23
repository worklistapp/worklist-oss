use std::collections::HashMap;
use uuid::Uuid;
use worklist_client_api::{WorkListDetailResponse, WorkListResponse};
use worklist_client_core::PublicResult;

use crate::RuntimeClient;
use crate::models::{AgentMembership, AgentWorkListDetail, AgentWorkListSummary};
use crate::projections::{
    PrincipalWorkListKeySource, WorkListContext, build_work_list_summary,
    decode_work_list_description_fallback, decode_work_list_payload_value,
    decode_work_list_title_fallback, extract_work_list_description, extract_work_list_title,
    make_read_error, missing_work_list_key_source_error, project_membership,
    resolve_work_list_key_for_principal_source, unreadable_work_list_context,
};

impl RuntimeClient {
    pub async fn list_work_lists(
        &self,
        password_stdin: bool,
    ) -> PublicResult<Vec<AgentWorkListSummary>> {
        let key_source = self.load_principal_work_list_key_source(
            password_stdin,
            "Password required to decrypt work lists.",
        )?;
        let mut client = self.authenticated_api_client().await?;
        let lists = client.list_work_lists().await?;
        Ok(lists
            .into_iter()
            .map(|list| self.project_work_list_summary(list, Some(&key_source)))
            .collect())
    }

    pub async fn get_work_list(
        &self,
        work_list_id: Uuid,
        password_stdin: bool,
    ) -> PublicResult<AgentWorkListDetail> {
        let key_source = self.load_principal_work_list_key_source(
            password_stdin,
            "Password required to decrypt work list data.",
        )?;
        let mut client = self.authenticated_api_client().await?;
        let detail = client.get_work_list(work_list_id).await?;
        Ok(self.project_work_list_detail(detail, Some(&key_source)))
    }

    pub(crate) fn build_work_list_contexts(
        &self,
        work_lists: &[WorkListResponse],
        key_source: Option<&PrincipalWorkListKeySource>,
    ) -> HashMap<Uuid, WorkListContext> {
        work_lists
            .iter()
            .map(|work_list| {
                (
                    work_list.id,
                    self.context_from_work_list_response(work_list, key_source),
                )
            })
            .collect()
    }

    pub(crate) fn context_from_work_list_detail(
        &self,
        work_list: &WorkListDetailResponse,
        key_source: Option<&PrincipalWorkListKeySource>,
    ) -> WorkListContext {
        self.context_from_work_list_response(&work_list.work_list, key_source)
    }

    fn context_from_work_list_response(
        &self,
        work_list: &WorkListResponse,
        key_source: Option<&PrincipalWorkListKeySource>,
    ) -> WorkListContext {
        let Some(key_source) = key_source else {
            return unreadable_work_list_context(None, missing_work_list_key_source_error());
        };

        let list_key = match resolve_work_list_key_for_principal_source(
            key_source,
            work_list.id,
            &work_list.membership.work_list_key_ciphertext,
        ) {
            Ok(list_key) => list_key,
            Err(err) => {
                return unreadable_work_list_context(None, make_read_error("work_list_key", err));
            }
        };

        let fallback_title = work_list
            .title_ciphertext
            .as_deref()
            .and_then(|ciphertext| {
                decode_work_list_title_fallback(ciphertext, &list_key, work_list.id)
            });
        let Some(payload_ciphertext) = work_list.payload_ciphertext.as_deref() else {
            return WorkListContext {
                work_list_title: fallback_title,
                list_key: Some(list_key),
                read_error: None,
            };
        };

        let (title, read_error) = match decode_work_list_payload_value(&list_key, payload_ciphertext)
        {
            Ok(payload) => (extract_work_list_title(&payload).or(fallback_title), None),
            Err(err) => (
                fallback_title,
                Some(make_read_error("work_list_payload", err)),
            ),
        };
        WorkListContext {
            work_list_title: title,
            list_key: Some(list_key),
            read_error,
        }
    }

    fn project_work_list_summary(
        &self,
        work_list: WorkListResponse,
        key_source: Option<&PrincipalWorkListKeySource>,
    ) -> AgentWorkListSummary {
        let membership = project_membership(&work_list.membership);

        let Some(key_source) = key_source else {
            return build_work_list_summary(
                work_list,
                membership,
                None,
                None,
                None,
                Some(missing_work_list_key_source_error()),
            );
        };

        self.project_work_list_summary_with_key_source(work_list, membership, key_source)
    }

    fn project_work_list_summary_with_key_source(
        &self,
        work_list: WorkListResponse,
        membership: AgentMembership,
        key_source: &PrincipalWorkListKeySource,
    ) -> AgentWorkListSummary {
        let list_key = match resolve_work_list_key_for_principal_source(
            key_source,
            work_list.id,
            &work_list.membership.work_list_key_ciphertext,
        ) {
            Ok(list_key) => list_key,
            Err(err) => {
                return build_work_list_summary(
                    work_list,
                    membership,
                    None,
                    None,
                    None,
                    Some(make_read_error("work_list_key", err)),
                );
            }
        };

        let fallback_title = work_list
            .title_ciphertext
            .as_deref()
            .and_then(|ciphertext| {
                decode_work_list_title_fallback(ciphertext, &list_key, work_list.id)
            });
        let fallback_description =
            work_list
                .description_ciphertext
                .as_deref()
                .and_then(|ciphertext| {
                    decode_work_list_description_fallback(ciphertext, &list_key, work_list.id)
                });
        let Some(payload_ciphertext) = work_list.payload_ciphertext.as_deref() else {
            return build_work_list_summary(
                work_list,
                membership,
                fallback_title,
                fallback_description,
                None,
                None,
            );
        };

        match decode_work_list_payload_value(&list_key, payload_ciphertext) {
            Ok(payload) => {
                let title = extract_work_list_title(&payload).or(fallback_title);
                let description = extract_work_list_description(&payload).or(fallback_description);
                build_work_list_summary(
                    work_list,
                    membership,
                    title,
                    description,
                    Some(payload),
                    None,
                )
            }
            Err(err) => build_work_list_summary(
                work_list,
                membership,
                fallback_title,
                fallback_description,
                None,
                Some(make_read_error("work_list_payload", err)),
            ),
        }
    }

    fn project_work_list_detail(
        &self,
        work_list: WorkListDetailResponse,
        key_source: Option<&PrincipalWorkListKeySource>,
    ) -> AgentWorkListDetail {
        let members = work_list.members.iter().map(project_membership).collect();
        AgentWorkListDetail {
            work_list: self.project_work_list_summary(work_list.work_list, key_source),
            members,
        }
    }
}
