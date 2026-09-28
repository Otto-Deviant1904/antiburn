//! Shared scheduler and TypeSafe executor for Jev-powered Burn Checks.

use std::future::Future;
use std::pin::Pin;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use antiburn_local::analysis::jev::{JevError, JevRequestBatch, JevResponse, MAX_REQUEST_TOKENS};
use sha2::{Digest, Sha256};
use tauri::Manager;
use tokio::sync::Notify;

use crate::jev_client::TypeSafeClient;
use crate::session_lifecycle::{SessionEvents, SessionRef};
use crate::store::{
    BurnCheckCandidate, BurnCheckInput, BurnCheckReservation, CachedAssessmentResponse, SessionKey,
    Store,
};

const PROVIDER_ID: &str = "typesafe-systemone";
const IDLE_SECS: i64 = 180;
const RETRY_ATTEMPTS: usize = 3;
const POLL_SECS: u64 = 60;
const CANDIDATES_PER_WAKE: usize = 16;

pub(crate) type WorkerFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;

pub(crate) struct CandidateExecution<'a> {
    pub(crate) app: &'a tauri::AppHandle,
    pub(crate) store: &'a Store,
    pub(crate) candidate: &'a BurnCheckCandidate,
    pub(crate) client: TypeSafeClient,
    pub(crate) handle: &'a WorkerHandle,
    pub(crate) key_generation: u64,
    pub(crate) events: &'a SessionEvents,
}

/// Supplies check policy to the shared scheduler and transport.
pub(crate) trait JevCheckWorker: Send + Sync {
    fn id(&self) -> &'static str;

    fn run_candidate<'a>(&'a self, execution: CandidateExecution<'a>) -> WorkerFuture<'a>;
}

/// Shared credential and wake state for Jev workers.
#[derive(Default)]
pub(crate) struct WorkerHandle {
    wake: Notify,
    api_key: RwLock<Option<String>>,
    key_generation: AtomicU64,
    authentication_rejected: AtomicBool,
}

impl WorkerHandle {
    /// Supply a key loaded from the native credential store.
    pub(crate) fn set_api_key(&self, api_key: Option<String>) {
        let mut current = self
            .api_key
            .write()
            .unwrap_or_else(|error| error.into_inner());
        *current = api_key;
        self.authentication_rejected.store(false, Ordering::Release);
        self.key_generation.fetch_add(1, Ordering::AcqRel);
        drop(current);
        self.wake.notify_one();
    }

    pub(crate) fn client(&self) -> Option<(TypeSafeClient, u64)> {
        let current = self
            .api_key
            .read()
            .unwrap_or_else(|error| error.into_inner());
        let key = current.clone()?;
        if self.authentication_rejected() {
            return None;
        }
        let generation = self.key_generation.load(Ordering::Acquire);
        TypeSafeClient::new(key)
            .ok()
            .map(|client| (client, generation))
    }

    pub(crate) fn key_is_current(&self, generation: u64) -> bool {
        let current = self
            .api_key
            .read()
            .unwrap_or_else(|error| error.into_inner());
        self.key_generation.load(Ordering::Acquire) == generation
            && current.is_some()
            && !self.authentication_rejected()
    }

    pub(crate) fn is_available(&self) -> bool {
        self.api_key
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .is_some()
    }

    pub(crate) fn authentication_rejected(&self) -> bool {
        self.authentication_rejected.load(Ordering::Acquire)
    }

    pub(crate) fn reject_authentication(&self) {
        self.authentication_rejected.store(true, Ordering::Release);
        self.wake.notify_one();
    }
}

/// Wake every registered check after source or Settings changes.
pub(crate) fn wake(app: &tauri::AppHandle) {
    app.state::<WorkerHandle>().wake.notify_one();
}

/// Run each registered check through the same bounded candidate scheduler.
pub(crate) fn spawn(app: &tauri::AppHandle) -> tauri::async_runtime::JoinHandle<()> {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let checks: [&dyn JevCheckWorker; 1] = [&crate::ignored_instructions_worker::CHECK];
        let mut lifecycle = app.state::<SessionEvents>().subscribe();
        let mut poll = tokio::time::interval(Duration::from_secs(POLL_SECS));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let handle = app.state::<WorkerHandle>();
            tokio::select! {
                () = handle.wake.notified() => {},
                _ = poll.tick() => {},
                event = lifecycle.recv() => {
                    match event {
                        Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {},
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                    }
                }
            }
            let Some((client, key_generation)) = handle.client() else {
                continue;
            };
            let store = (*app.state::<Store>()).clone();
            let events = app.state::<SessionEvents>();
            for check in checks {
                if !handle.key_is_current(key_generation) {
                    break;
                }
                let candidates = match store.burn_check_candidates(
                    check.id(),
                    unix_now(),
                    IDLE_SECS,
                    CANDIDATES_PER_WAKE,
                ) {
                    Ok(candidates) => candidates,
                    Err(error) => {
                        ::tracing::warn!(
                            event = "burn_check_candidates_failed",
                            check_id = check.id(),
                            error = %error
                        );
                        continue;
                    }
                };
                for candidate in candidates {
                    if !handle.key_is_current(key_generation) {
                        break;
                    }
                    let result = check
                        .run_candidate(CandidateExecution {
                            app: &app,
                            store: &store,
                            candidate: &candidate,
                            client: client.clone(),
                            handle: &handle,
                            key_generation,
                            events: &events,
                        })
                        .await;
                    if candidate.historical {
                        crate::jev_settings::progress_changed(&app);
                    }
                    if let Err(error) = result {
                        ::tracing::warn!(
                            event = "burn_check_assessment_failed",
                            check_id = check.id(),
                            agent = %candidate.session.key.agent,
                            error = %error,
                        );
                    }
                }
            }
        }
    })
}

pub(crate) struct BatchExecution<'a> {
    pub(crate) app: &'a tauri::AppHandle,
    pub(crate) store: &'a Store,
    pub(crate) input: &'a BurnCheckInput,
    pub(crate) client: TypeSafeClient,
    pub(crate) handle: &'a WorkerHandle,
    pub(crate) key_generation: u64,
    pub(crate) events: &'a SessionEvents,
    pub(crate) idle_secs: i64,
    pub(crate) lease_secs: i64,
}

/// Execute one validated request with shared cache, reservation, retry, and
/// cancellation behavior. The request digest contains no check-specific ID.
pub(crate) async fn execute_jev_batch(
    execution: BatchExecution<'_>,
    batch: JevRequestBatch,
) -> Result<JevResponse, JevError> {
    let BatchExecution {
        app,
        store,
        input,
        client,
        handle,
        key_generation,
        events,
        idle_secs,
        lease_secs,
    } = execution;
    if let Some(cached) = store
        .cached_assessment_response(PROVIDER_ID, &batch.digest, unix_now())
        .map_err(|_| JevError::ProviderUnavailable)?
    {
        ::tracing::debug!(
            event = "typesafe_request_completed",
            model = %batch.request.model,
            cache_hit = true,
            request_bytes = batch.serialized_bytes,
            question_count = batch.request.questions.len(),
            work_item_count = batch.work_item_ids.len(),
            input_tokens = cached.input_tokens,
            output_tokens = 0,
            elapsed_ms = 0,
        );
        let cache_hit_id = request_cache_identity(input, &batch.digest);
        store
            .record_burn_check_cache_hit(
                input,
                PROVIDER_ID,
                &batch.request.model,
                &input.check_id,
                &cache_hit_id,
            )
            .map_err(|_| JevError::ProviderUnavailable)?;
        crate::jev_settings::changed(app);
        return decode_cached_response(cached, &batch);
    }
    for attempt in 0..RETRY_ATTEMPTS {
        let started = std::time::Instant::now();
        if !handle.key_is_current(key_generation) || session_is_active(events, &input.key) {
            return Err(JevError::Cancelled);
        }
        if !store
            .renew_burn_check_assessment(input, unix_now(), lease_secs, idle_secs)
            .map_err(|_| JevError::ProviderUnavailable)?
        {
            return Err(JevError::Cancelled);
        }
        let reservation = store
            .reserve_burn_check_usage(
                input,
                PROVIDER_ID,
                &batch.request.model,
                MAX_REQUEST_TOKENS,
                unix_now(),
                idle_secs,
            )
            .map_err(|_| JevError::ProviderUnavailable)?;
        let BurnCheckReservation::Reserved(reservation_id) = reservation else {
            return Err(JevError::Cancelled);
        };
        let request = batch.request.clone();
        let call_client = client.clone();
        let mut call = tauri::async_runtime::spawn_blocking(move || call_client.evaluate(&request));
        let response = loop {
            tokio::select! {
                result = &mut call => {
                    break match result {
                        Ok(result) => result,
                        Err(_) => {
                            store.settle_burn_check_usage(&reservation_id, None, unix_now())
                                .map_err(|_| JevError::ProviderUnavailable)?;
                            crate::jev_settings::changed(app);
                            return Err(JevError::RequestOutcomeUnknown);
                        }
                    };
                }
                () = tokio::time::sleep(Duration::from_millis(250)) => {
                    if !handle.key_is_current(key_generation) || session_is_active(events, &input.key) {
                        drop(call);
                        store.settle_burn_check_usage(&reservation_id, None, unix_now())
                            .map_err(|_| JevError::ProviderUnavailable)?;
                        crate::jev_settings::changed(app);
                        return Err(JevError::Cancelled);
                    }
                }
            }
        };
        match response {
            Ok(response) => {
                ::tracing::debug!(
                    event = "typesafe_request_completed",
                    model = %response.model,
                    cache_hit = false,
                    attempt = attempt + 1,
                    request_bytes = batch.serialized_bytes,
                    question_count = batch.request.questions.len(),
                    work_item_count = batch.work_item_ids.len(),
                    input_tokens = response.usage.input_tokens,
                    output_tokens = response.usage.output_tokens,
                    elapsed_ms = started.elapsed().as_millis(),
                );
                let response_json =
                    serde_json::to_string(&response).map_err(|_| JevError::ResponseDecode)?;
                store
                    .record_burn_check_response(
                        &reservation_id,
                        CachedAssessmentResponse {
                            provider: PROVIDER_ID.to_owned(),
                            request_digest: batch.digest,
                            returned_model: response.model.clone(),
                            response_json,
                            input_tokens: response.usage.input_tokens,
                            output_tokens: response.usage.output_tokens,
                            created_at_epoch: unix_now(),
                        },
                    )
                    .map_err(|_| JevError::ProviderUnavailable)?;
                crate::jev_settings::changed(app);
                if response.usage.input_tokens > MAX_REQUEST_TOKENS {
                    return Err(JevError::ResponseUsageExceeded);
                }
                return Ok(response);
            }
            Err(error)
                if attempt + 1 < RETRY_ATTEMPTS && retry_delay(&error, attempt).is_some() =>
            {
                ::tracing::debug!(
                    event = "typesafe_request_failed",
                    model = %batch.request.model,
                    attempt = attempt + 1,
                    request_bytes = batch.serialized_bytes,
                    question_count = batch.request.questions.len(),
                    work_item_count = batch.work_item_ids.len(),
                    failure_category = error_category(&error),
                    error_detail = ?error,
                    retry_delay_ms = retry_delay(&error, attempt).unwrap_or_default().as_millis(),
                    elapsed_ms = started.elapsed().as_millis(),
                );
                store
                    .settle_burn_check_usage(&reservation_id, None, unix_now())
                    .map_err(|_| JevError::ProviderUnavailable)?;
                crate::jev_settings::changed(app);
                tokio::time::sleep(retry_delay(&error, attempt).unwrap_or_default()).await;
            }
            Err(error) => {
                ::tracing::debug!(
                    event = "typesafe_request_failed",
                    model = %batch.request.model,
                    attempt = attempt + 1,
                    request_bytes = batch.serialized_bytes,
                    question_count = batch.request.questions.len(),
                    work_item_count = batch.work_item_ids.len(),
                    failure_category = error_category(&error),
                    error_detail = ?error,
                    retry_delay_ms = 0,
                    elapsed_ms = started.elapsed().as_millis(),
                );
                store
                    .settle_burn_check_usage(&reservation_id, None, unix_now())
                    .map_err(|_| JevError::ProviderUnavailable)?;
                crate::jev_settings::changed(app);
                return Err(error);
            }
        }
    }
    Err(JevError::ProviderUnavailable)
}

fn decode_cached_response(
    cached: CachedAssessmentResponse,
    batch: &JevRequestBatch,
) -> Result<JevResponse, JevError> {
    let mut response: JevResponse =
        serde_json::from_str(&cached.response_json).map_err(|_| JevError::ResponseDecode)?;
    antiburn_local::analysis::jev::validate_jev_response(&response, &batch.request)?;
    if response.model != cached.returned_model {
        return Err(JevError::ResponseModelMismatch);
    }
    if cached.input_tokens > MAX_REQUEST_TOKENS {
        return Err(JevError::ResponseUsageExceeded);
    }
    response.usage = antiburn_local::analysis::jev::JevUsage {
        input_tokens: 0,
        output_tokens: 0,
    };
    Ok(response)
}

pub(crate) fn retry_delay(error: &JevError, attempt: usize) -> Option<Duration> {
    match error {
        JevError::RateLimited { retry_after } | JevError::ProviderOverloaded { retry_after } => {
            match retry_after {
                Some(delay) if *delay <= Duration::from_secs(240) => Some(*delay),
                Some(_) => None,
                None => Some(Duration::from_secs(1_u64 << attempt.min(3))),
            }
        }
        _ => None,
    }
}

fn session_is_active(events: &SessionEvents, key: &SessionKey) -> bool {
    events
        .presence(&[SessionRef::from(key)])
        .present
        .iter()
        .any(|session| !session.quiet)
}

pub(crate) fn error_category(error: &JevError) -> &'static str {
    match error {
        JevError::AuthenticationRejected => "authentication_rejected",
        JevError::InvalidRequestSchema => "invalid_request_schema",
        JevError::RateLimited { .. } => "rate_limited",
        JevError::ProviderOverloaded { .. } => "provider_overloaded",
        JevError::ProviderUnavailable => "provider_unavailable",
        JevError::RequestOutcomeUnknown => "outcome_unknown",
        JevError::RequestSerialization
        | JevError::EmptyQuestions
        | JevError::QuestionLimitExceeded
        | JevError::UnsupportedModel
        | JevError::RequestTooLarge { .. } => "invalid_request",
        JevError::ResponseModelMismatch
        | JevError::ResponseAnswerCountMismatch
        | JevError::ResponseAnswerMissing
        | JevError::ResponseAnswerTypeMismatch
        | JevError::InvalidChoiceDistribution
        | JevError::InvalidNoulProbability
        | JevError::InvalidScoreDistribution
        | JevError::InvalidProbabilitySum
        | JevError::WorkItemHasNoAnswers => "invalid_response",
        JevError::ResponseTooLarge => "response_too_large",
        JevError::ResponseDecode => "response_decode",
        JevError::ResponseUsageExceeded => "response_usage_exceeded",
        JevError::ProgressStorageFailure => "progress_storage_failed",
        JevError::InvalidCheckContext | JevError::InvalidCheckPlan => "invalid_assessment_plan",
        JevError::Cancelled => "cancelled",
    }
}

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

pub(crate) fn request_cache_identity(input: &BurnCheckInput, request_digest: &str) -> String {
    let digest = Sha256::digest(
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            input.key.environment_key,
            input.key.agent,
            input.key.session_id,
            input.check_id,
            input.input_revision,
            request_digest
        )
        .as_bytes(),
    );
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_retry_delay_uses_retry_after_and_bounded_backoff() {
        assert_eq!(
            retry_delay(
                &JevError::RateLimited {
                    retry_after: Some(Duration::from_secs(12)),
                },
                0,
            ),
            Some(Duration::from_secs(12))
        );
        assert_eq!(
            retry_delay(&JevError::ProviderOverloaded { retry_after: None }, 1),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            retry_delay(
                &JevError::RateLimited {
                    retry_after: Some(Duration::from_secs(300)),
                },
                0,
            ),
            None
        );
    }
}
