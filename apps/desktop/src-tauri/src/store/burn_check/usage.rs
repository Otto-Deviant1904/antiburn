use super::*;

const MAX_USAGE_AGGREGATES: usize = 8;
const PINNED_PRICE_VERSION: &str = "typesafe-model-catalog-2026-09-25";
const PINNED_INPUT_NANODOLLARS_PER_TOKEN: u64 = 42;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BurnCheckUsageSummary {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub confirmed_calls: u64,
    pub cache_hits: u64,
    pub unknown_outcomes: u64,
    pub estimated_usd: Option<String>,
    pub last_used_at_epoch: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub(super) struct UsageLedgerSummary {
    aggregates: Vec<ModelUsageAggregate>,
    unknown_outcomes: u64,
    cache_hits: u64,
    last_unknown_at_epoch: Option<i64>,
    unpriced_usage: bool,
    overflow_input_tokens: u64,
    overflow_output_tokens: u64,
    overflow_confirmed_calls: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ModelUsageAggregate {
    provider: String,
    check_id: String,
    model: String,
    price_version: Option<String>,
    input_tokens: u64,
    output_tokens: u64,
    confirmed_calls: u64,
    #[serde(default)]
    cache_hits: u64,
    estimated_cost_nanos: Option<u64>,
    last_used_at_epoch: i64,
}

impl Store {
    /// Reserve the conservative request maximum before provider dispatch.
    pub fn reserve_burn_check_usage(
        &self,
        input: &BurnCheckInput,
        provider: &str,
        model: &str,
        reserved_input_tokens: u64,
        now_epoch: i64,
        idle_secs: i64,
    ) -> anyhow::Result<BurnCheckReservation> {
        if provider.is_empty() || provider.len() > 128 || model.is_empty() || model.len() > 128 {
            anyhow::bail!("Burn Check usage identity is invalid");
        }
        let mut connection = self.lock();
        let transaction = connection.transaction()?;
        let row: Option<(i64, String, Option<i64>, bool)> = transaction
            .query_row(
                "SELECT request_count, status, lease_expires_at_epoch,
                        EXISTS (
                            SELECT 1 FROM session AS s
                            JOIN session_evidence AS e
                              ON e.environment_key = s.environment_key AND e.agent = s.agent
                             AND e.session_id = s.session_id
                             AND e.status = 'ready'
                             AND e.analyzed_generation = s.source_generation
                             AND e.processed_fingerprint IS s.source_fingerprint
                             AND e.published_fence = ?6
                             AND e.parser_revision = ?13
                             AND e.evidence_schema_revision = ?14
                            WHERE s.environment_key = ?1 AND s.agent = ?2 AND s.session_id = ?3
                              AND s.incarnation = ?8 AND s.source_generation = ?9
                              AND s.source_fingerprint IS ?10 AND s.activity_cursor = ?11
                              AND s.updated_at_epoch <= ?7 - ?12
                        )
                   FROM burn_check_assessment
                  WHERE environment_key = ?1 AND agent = ?2 AND session_id = ?3
                    AND check_id = ?4 AND input_revision = ?5",
                rusqlite::params![
                    input.key.environment_key,
                    input.key.agent,
                    input.key.session_id,
                    input.check_id,
                    input.input_revision,
                    input.published_fence,
                    now_epoch,
                    input.incarnation,
                    input.source_generation,
                    input.source_fingerprint,
                    input.activity_cursor,
                    idle_secs.max(0),
                    antiburn_local::analysis::PARSER_REVISION,
                    antiburn_local::analysis::EVIDENCE_SCHEMA_REVISION,
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((request_count, status, lease_expires, input_is_current)) = row else {
            transaction.commit()?;
            return Ok(BurnCheckReservation::Stale);
        };
        if status != "running"
            || lease_expires.is_none_or(|expiry| expiry <= now_epoch)
            || !input_is_current
        {
            transaction.commit()?;
            return Ok(BurnCheckReservation::Stale);
        }
        let raw = internal_value_in(&transaction, USAGE_LEDGER_KEY)?;
        let mut ledger = raw
            .as_deref()
            .map(serde_json::from_str::<UsageLedger>)
            .transpose()?
            .unwrap_or_default();
        ledger
            .reservations
            .retain(|reservation| reservation.expires_at_epoch > now_epoch);
        let attempt = request_count.saturating_add(1).to_string();
        let reservation_id = digest_parts([
            input.key.environment_key.as_str(),
            input.key.agent.as_str(),
            input.key.session_id.as_str(),
            input.check_id.as_str(),
            input.input_revision.as_str(),
            attempt.as_str(),
        ]);
        let session_key = digest_parts([
            input.key.environment_key.as_str(),
            input.key.agent.as_str(),
            input.key.session_id.as_str(),
        ]);
        ledger.reservations.push(UsageReservation {
            id: reservation_id.clone(),
            session_key,
            provider: provider.to_owned(),
            check_id: input.check_id.clone(),
            model: model.to_owned(),
            input_tokens: reserved_input_tokens,
            expires_at_epoch: now_epoch.saturating_add(USAGE_WINDOW_SECS),
            settled: false,
            unknown_recorded: false,
        });
        write_json_setting(&transaction, USAGE_LEDGER_KEY, &ledger)?;
        transaction.execute(
            "UPDATE burn_check_assessment SET request_count = request_count + 1,
                    updated_at_epoch = ?6
              WHERE environment_key = ?1 AND agent = ?2 AND session_id = ?3
                AND check_id = ?4 AND input_revision = ?5 AND status = 'running'",
            rusqlite::params![
                input.key.environment_key,
                input.key.agent,
                input.key.session_id,
                input.check_id,
                input.input_revision,
                now_epoch,
            ],
        )?;
        transaction.commit()?;
        Ok(BurnCheckReservation::Reserved(reservation_id))
    }

    /// Settle a reservation once; `None` keeps its safety bound for an unknown outcome.
    pub fn settle_burn_check_usage(
        &self,
        reservation_id: &str,
        actual_input_tokens: Option<u64>,
        now_epoch: i64,
    ) -> anyhow::Result<()> {
        let mut connection = self.lock();
        let transaction = connection.transaction()?;
        let raw = internal_value_in(&transaction, USAGE_LEDGER_KEY)?;
        let mut ledger = raw
            .as_deref()
            .map(serde_json::from_str::<UsageLedger>)
            .transpose()?
            .unwrap_or_default();
        ledger
            .reservations
            .retain(|reservation| reservation.expires_at_epoch > now_epoch);
        let Some(index) = ledger
            .reservations
            .iter()
            .position(|reservation| reservation.id == reservation_id)
        else {
            anyhow::bail!("Burn Check usage reservation is missing");
        };
        let reservation = &mut ledger.reservations[index];
        if let Some(actual) = actual_input_tokens {
            if !reservation.settled {
                record_confirmed_usage(&mut ledger.summary, reservation, actual, 0, now_epoch);
                reservation.settled = true;
            }
            reservation.input_tokens = actual;
        } else if !reservation.unknown_recorded {
            ledger.summary.unknown_outcomes = ledger.summary.unknown_outcomes.saturating_add(1);
            ledger.summary.last_unknown_at_epoch = Some(now_epoch);
            reservation.unknown_recorded = true;
        }
        write_json_setting(&transaction, USAGE_LEDGER_KEY, &ledger)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn record_burn_check_cache_hit(
        &self,
        input: &BurnCheckInput,
        provider: &str,
        model: &str,
        check_id: &str,
        attempt_id: &str,
    ) -> anyhow::Result<()> {
        let mut connection = self.lock();
        let transaction = connection.transaction()?;
        let last_hit: Option<String> = transaction
            .query_row(
                "SELECT COALESCE(last_usage_cache_hit_id, '') FROM burn_check_assessment
                  WHERE environment_key = ?1 AND agent = ?2 AND session_id = ?3
                    AND check_id = ?4 AND input_revision = ?5 AND status = 'running'",
                rusqlite::params![
                    input.key.environment_key,
                    input.key.agent,
                    input.key.session_id,
                    input.check_id,
                    input.input_revision,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if last_hit.as_deref() == Some(attempt_id) {
            transaction.commit()?;
            return Ok(());
        }
        let updated = transaction.execute(
            "UPDATE burn_check_assessment SET last_usage_cache_hit_id = ?6
              WHERE environment_key = ?1 AND agent = ?2 AND session_id = ?3
                AND check_id = ?4 AND input_revision = ?5 AND status = 'running'",
            rusqlite::params![
                input.key.environment_key,
                input.key.agent,
                input.key.session_id,
                input.check_id,
                input.input_revision,
                attempt_id,
            ],
        )?;
        if updated != 1 {
            anyhow::bail!("Burn Check cache hit is stale");
        }
        let raw = internal_value_in(&transaction, USAGE_LEDGER_KEY)?;
        let mut ledger = raw
            .as_deref()
            .map(serde_json::from_str::<UsageLedger>)
            .transpose()?
            .unwrap_or_default();
        if !provider.is_empty()
            && !model.is_empty()
            && !check_id.is_empty()
            && !attempt_id.is_empty()
        {
            ledger.summary.cache_hits = ledger.summary.cache_hits.saturating_add(1);
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let price_version = (model == antiburn_local::analysis::jev::PINNED_MODEL)
                .then(|| PINNED_PRICE_VERSION.to_owned());
            let index = ledger
                .summary
                .aggregates
                .iter()
                .position(|aggregate| {
                    aggregate.provider == provider
                        && aggregate.check_id == check_id
                        && aggregate.model == model
                        && aggregate.price_version == price_version
                })
                .unwrap_or_else(|| {
                    if ledger.summary.aggregates.len() >= MAX_USAGE_AGGREGATES {
                        return usize::MAX;
                    }
                    ledger.summary.aggregates.push(ModelUsageAggregate {
                        provider: provider.to_owned(),
                        check_id: check_id.to_owned(),
                        model: model.to_owned(),
                        price_version: price_version.clone(),
                        input_tokens: 0,
                        output_tokens: 0,
                        confirmed_calls: 0,
                        cache_hits: 0,
                        estimated_cost_nanos: price_version.as_ref().map(|_| 0),
                        last_used_at_epoch: now,
                    });
                    ledger.summary.aggregates.len() - 1
                });
            if let Some(aggregate) = ledger.summary.aggregates.get_mut(index) {
                aggregate.cache_hits = aggregate.cache_hits.saturating_add(1);
                aggregate.last_used_at_epoch = now;
            }
        }
        write_json_setting(&transaction, USAGE_LEDGER_KEY, &ledger)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn burn_check_usage_summary(&self) -> anyhow::Result<BurnCheckUsageSummary> {
        let connection = self.lock();
        let Some(raw) = internal_value_in(&connection, USAGE_LEDGER_KEY)? else {
            return Ok(BurnCheckUsageSummary::default());
        };
        let ledger: UsageLedger = serde_json::from_str(&raw)?;
        let mut summary = BurnCheckUsageSummary {
            input_tokens: ledger.summary.overflow_input_tokens,
            output_tokens: ledger.summary.overflow_output_tokens,
            confirmed_calls: ledger.summary.overflow_confirmed_calls,
            cache_hits: ledger.summary.cache_hits,
            unknown_outcomes: ledger.summary.unknown_outcomes,
            ..BurnCheckUsageSummary::default()
        };
        summary.last_used_at_epoch = ledger.summary.last_unknown_at_epoch;
        let mut total_cost_nanos = 0_u64;
        for aggregate in &ledger.summary.aggregates {
            summary.last_used_at_epoch = Some(
                summary
                    .last_used_at_epoch
                    .unwrap_or(i64::MIN)
                    .max(aggregate.last_used_at_epoch),
            );
            summary.input_tokens = summary.input_tokens.saturating_add(aggregate.input_tokens);
            summary.output_tokens = summary
                .output_tokens
                .saturating_add(aggregate.output_tokens);
            summary.confirmed_calls = summary
                .confirmed_calls
                .saturating_add(aggregate.confirmed_calls);
            summary.cache_hits = summary.cache_hits.max(aggregate.cache_hits);
            if let Some(cost) = aggregate.estimated_cost_nanos {
                total_cost_nanos = total_cost_nanos.saturating_add(cost);
            }
        }
        if !ledger.summary.unpriced_usage {
            summary.estimated_usd = Some(format_usd_nanos(total_cost_nanos));
        }
        Ok(summary)
    }
}

pub(super) fn record_confirmed_usage(
    summary: &mut UsageLedgerSummary,
    reservation: &UsageReservation,
    input_tokens: u64,
    output_tokens: u64,
    at_epoch: i64,
) {
    let price_version = (reservation.model == antiburn_local::analysis::jev::PINNED_MODEL)
        .then(|| PINNED_PRICE_VERSION.to_owned());
    let cost = price_version
        .as_ref()
        .map(|_| input_tokens.saturating_mul(PINNED_INPUT_NANODOLLARS_PER_TOKEN));
    let existing = summary.aggregates.iter().position(|aggregate| {
        aggregate.provider == reservation.provider
            && aggregate.check_id == reservation.check_id
            && aggregate.model == reservation.model
            && aggregate.price_version == price_version
    });
    let index = existing.or_else(|| {
        if summary.aggregates.len() >= MAX_USAGE_AGGREGATES {
            return None;
        }
        summary.aggregates.push(ModelUsageAggregate {
            provider: reservation.provider.clone(),
            check_id: reservation.check_id.clone(),
            model: reservation.model.clone(),
            price_version: price_version.clone(),
            input_tokens: 0,
            output_tokens: 0,
            confirmed_calls: 0,
            cache_hits: 0,
            estimated_cost_nanos: cost.map(|_| 0),
            last_used_at_epoch: at_epoch,
        });
        Some(summary.aggregates.len() - 1)
    });
    if let Some(index) = index {
        let aggregate = &mut summary.aggregates[index];
        aggregate.input_tokens = aggregate.input_tokens.saturating_add(input_tokens);
        aggregate.output_tokens = aggregate.output_tokens.saturating_add(output_tokens);
        aggregate.confirmed_calls = aggregate.confirmed_calls.saturating_add(1);
        aggregate.last_used_at_epoch = at_epoch;
        if let (Some(total), Some(cost)) = (&mut aggregate.estimated_cost_nanos, cost) {
            *total = total.saturating_add(cost);
        } else {
            summary.unpriced_usage = true;
        }
    } else {
        summary.overflow_input_tokens = summary.overflow_input_tokens.saturating_add(input_tokens);
        summary.overflow_output_tokens =
            summary.overflow_output_tokens.saturating_add(output_tokens);
        summary.overflow_confirmed_calls = summary.overflow_confirmed_calls.saturating_add(1);
        summary.unpriced_usage = true;
    }
}

fn format_usd_nanos(nanos: u64) -> String {
    let whole = nanos / 1_000_000_000;
    let mut fraction = format!("{:09}", nanos % 1_000_000_000);
    while fraction.len() > 2 && fraction.ends_with('0') {
        fraction.pop();
    }
    format!("${whole}.{fraction}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reservation(model: &str) -> UsageReservation {
        UsageReservation {
            id: "attempt".to_owned(),
            session_key: "session-digest".to_owned(),
            provider: "typesafe-systemone".to_owned(),
            check_id: "ignored_instructions".to_owned(),
            model: model.to_owned(),
            input_tokens: 0,
            expires_at_epoch: 100,
            settled: false,
            unknown_recorded: false,
        }
    }

    #[test]
    fn pinned_model_cost_uses_the_price_version_at_settlement() {
        let mut summary = UsageLedgerSummary::default();
        record_confirmed_usage(
            &mut summary,
            &reservation(antiburn_local::analysis::jev::PINNED_MODEL),
            1_000_000,
            24,
            50,
        );
        assert_eq!(format_usd_nanos(42_000_000), "$0.042");
        assert_eq!(summary.aggregates.len(), 1);
        assert_eq!(
            summary.aggregates[0].price_version.as_deref(),
            Some(PINNED_PRICE_VERSION)
        );
        assert_eq!(summary.aggregates[0].estimated_cost_nanos, Some(42_000_000));
        assert_eq!(summary.aggregates[0].input_tokens, 1_000_000);
    }

    #[test]
    fn unknown_model_usage_has_no_estimated_dollar_value() {
        let mut summary = UsageLedgerSummary::default();
        record_confirmed_usage(&mut summary, &reservation("jev-new-model"), 100, 0, 50);
        assert!(summary.unpriced_usage);
        assert_eq!(summary.aggregates[0].estimated_cost_nanos, None);
    }
}
