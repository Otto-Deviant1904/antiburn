//! Bounded TypeSafe System One transport.

use std::io::Read;
use std::time::Duration;

use crate::jev_config::system_one_endpoint;
use antiburn_local::analysis::jev::{
    JevAnswer, JevError, JevRequest, JevResponse, MAX_RESPONSE_BYTES, highest_probability_choice,
    validate_jev_request, validate_jev_response,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The client keeps the key private and never includes it in debug output.
#[derive(Clone)]
pub(crate) struct TypeSafeClient {
    api_key: String,
}

impl TypeSafeClient {
    pub(crate) fn new(api_key: String) -> Result<Self, JevError> {
        if api_key.trim().is_empty() {
            return Err(JevError::AuthenticationRejected);
        }
        Ok(Self { api_key })
    }

    pub(crate) fn evaluate(&self, request: &JevRequest) -> Result<JevResponse, JevError> {
        validate_jev_request(request)?;
        let response = client()
            .post(system_one_endpoint())
            .bearer_auth(&self.api_key)
            .json(request)
            .send()
            .map_err(|error| {
                if error.is_timeout() {
                    JevError::RequestOutcomeUnknown
                } else if error.is_connect() {
                    JevError::ProviderUnavailable
                } else {
                    JevError::RequestOutcomeUnknown
                }
            })?;
        let status = response.status();
        if !status.is_success() {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .map(Duration::from_secs);
            return Err(match status.as_u16() {
                401 | 403 => JevError::AuthenticationRejected,
                400 | 422 => JevError::InvalidRequestSchema,
                429 => JevError::RateLimited { retry_after },
                500..=599 => JevError::ProviderOverloaded { retry_after },
                _ => JevError::ProviderUnavailable,
            });
        }
        let response = read_bounded_response(response)?;
        let response: JevResponse =
            serde_json::from_slice(&response).map_err(|_| JevError::ResponseDecode)?;
        validate_jev_response(&response, request)?;
        let (mismatch_count, largest_gap) = choice_mismatches(&response);
        if mismatch_count > 0 {
            ::tracing::warn!(
                event = "typesafe_choice_probability_mismatch",
                model = %response.model,
                question_count = request.questions.len(),
                mismatch_count,
                largest_probability_gap = largest_gap,
                input_tokens = response.usage.input_tokens,
                output_tokens = response.usage.output_tokens,
            );
        }
        Ok(response)
    }
}

fn choice_mismatches(response: &JevResponse) -> (usize, f64) {
    response
        .answers
        .values()
        .fold((0, 0.0), |(count, gap), answer| {
            let JevAnswer::Choice {
                choice,
                probabilities,
                ..
            } = answer
            else {
                return (count, gap);
            };
            let Some(highest) = highest_probability_choice(choice, probabilities) else {
                return (count, gap);
            };
            if highest == choice {
                return (count, gap);
            }
            let difference = probabilities[highest] - probabilities[choice];
            (count + 1, gap.max(difference))
        })
}

fn client() -> &'static reqwest::blocking::Client {
    static CLIENT: std::sync::OnceLock<reqwest::blocking::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        reqwest::blocking::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("a client with no custom TLS material always builds")
    })
}

fn read_bounded_response(mut response: reqwest::blocking::Response) -> Result<Vec<u8>, JevError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(JevError::ResponseTooLarge);
    }
    let mut body = Vec::with_capacity(MAX_RESPONSE_BYTES.min(16 * 1024));
    response
        .by_ref()
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| JevError::RequestOutcomeUnknown)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(JevError::ResponseTooLarge);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use antiburn_local::analysis::jev::{JevAnswer, JevQuestion, JevUsage};
    use serde_json::json;
    use std::collections::BTreeMap;

    use super::*;

    #[tokio::test]
    async fn blocking_transport_is_created_on_a_blocking_thread() {
        let client = TypeSafeClient::new("synthetic-key".to_owned()).unwrap();
        tokio::task::spawn_blocking(move || {
            drop(client);
            assert!(std::ptr::eq(super::client(), super::client()));
        })
        .await
        .unwrap();
    }

    #[test]
    fn typed_response_decode_matches_the_validated_request_contract() {
        let request = JevRequest {
            model: "jev-1.13.0".to_owned(),
            state: json!({"event_id": "synthetic-event"}),
            questions: BTreeMap::from([(
                "issue".to_owned(),
                JevQuestion::Choice {
                    instructions: json!("Is this a conflict?"),
                    criteria: BTreeMap::from([
                        ("yes".to_owned(), json!("Conflict")),
                        ("no".to_owned(), json!("No conflict")),
                    ]),
                },
            )]),
        };
        let value = json!({
            "model": "jev-1.13.0",
            "answers": {
                "issue": {
                    "type": "choice",
                    "choice": "yes",
                    "probabilities": {"yes": 0.9, "no": 0.1},
                    "confidence": 0.8
                }
            },
            "usage": {"input_tokens": 12, "output_tokens": 1}
        });
        let response: JevResponse = serde_json::from_value(value).unwrap();
        assert_eq!(validate_jev_response(&response, &request), Ok(()));
        assert_eq!(
            response.usage,
            JevUsage {
                input_tokens: 12,
                output_tokens: 1
            }
        );
        assert!(
            matches!(response.answers.get("issue"), Some(JevAnswer::Choice { choice, .. }) if choice == "yes")
        );
        assert_eq!(choice_mismatches(&response), (0, 0.0));
        let mut inconsistent = response;
        if let Some(JevAnswer::Choice { choice, .. }) = inconsistent.answers.get_mut("issue") {
            *choice = "no".to_owned();
        }
        assert_eq!(validate_jev_response(&inconsistent, &request), Ok(()));
        let (count, gap) = choice_mismatches(&inconsistent);
        assert_eq!(count, 1);
        assert!((gap - 0.8).abs() < 0.000_001);
    }
}
