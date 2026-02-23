use crate::domain::types::{
    StrategyOutcomeEvent, StrategyOutcomeStats, StrategyParameterPriors, StrategyTemplateKey,
    TemplateActivationState, TemplateVersion,
};
use crate::storage::stable;

const AUTO_DEACTIVATE_DETERMINISTIC_STREAK: u32 = 3;

pub fn record_outcome(event: StrategyOutcomeEvent) -> Result<StrategyOutcomeStats, String> {
    let observed_at_ns = event.observed_at_ns;
    let stats = stable::record_strategy_outcome(event)?;
    let learned = apply_learning_updates(stats);
    let persisted = stable::upsert_strategy_outcome_stats(learned)?;
    maybe_auto_deactivate_on_deterministic_failures(&persisted, observed_at_ns)?;
    Ok(persisted)
}

pub fn outcome_stats(
    key: &StrategyTemplateKey,
    version: &TemplateVersion,
) -> Option<StrategyOutcomeStats> {
    stable::strategy_outcome_stats(key, version)
}

fn apply_learning_updates(mut stats: StrategyOutcomeStats) -> StrategyOutcomeStats {
    if stats.total_runs == 0 {
        stats.confidence_bps = 0;
        stats.ranking_score_bps = 0;
        stats.parameter_priors = StrategyParameterPriors::default();
        return stats;
    }

    let total = stats.total_runs.max(1);
    let success_rate_bps = ratio_bps(stats.success_runs, total);
    let deterministic_rate_bps = ratio_bps(stats.deterministic_failures, total);
    let nondeterministic_rate_bps = ratio_bps(stats.nondeterministic_failures, total);

    let deterministic_penalty = deterministic_rate_bps / 2;
    let nondeterministic_penalty = nondeterministic_rate_bps / 4;
    let confidence = success_rate_bps
        .saturating_sub(deterministic_penalty)
        .saturating_sub(nondeterministic_penalty);

    let sample_bonus = u16::try_from(stats.total_runs.min(50))
        .unwrap_or(50)
        .saturating_mul(40);
    let ranking = ((u32::from(confidence) * 8) / 10)
        .saturating_add(u32::from(sample_bonus))
        .min(10_000) as u16;

    let slippage = 100u16
        .saturating_add(deterministic_rate_bps / 100)
        .saturating_add(nondeterministic_rate_bps / 200)
        .clamp(25, 500);
    let gas_buffer = 120u16
        .saturating_add(deterministic_rate_bps / 200)
        .saturating_add(nondeterministic_rate_bps / 50)
        .clamp(100, 500);

    stats.confidence_bps = confidence.min(10_000);
    stats.ranking_score_bps = ranking;
    stats.parameter_priors = StrategyParameterPriors {
        slippage_bps: slippage,
        gas_buffer_bps: gas_buffer,
    };
    stats
}

fn ratio_bps(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let bps = numerator
        .saturating_mul(10_000)
        .checked_div(denominator)
        .unwrap_or(0);
    u16::try_from(bps).unwrap_or(10_000).min(10_000)
}

fn maybe_auto_deactivate_on_deterministic_failures(
    stats: &StrategyOutcomeStats,
    observed_at_ns: u64,
) -> Result<(), String> {
    if stats.deterministic_failure_streak < AUTO_DEACTIVATE_DETERMINISTIC_STREAK {
        return Ok(());
    }
    let currently_enabled = stable::strategy_template_activation(&stats.key, &stats.version)
        .map(|state| state.enabled)
        .unwrap_or(false);
    if !currently_enabled {
        return Ok(());
    }

    stable::set_strategy_template_activation(TemplateActivationState {
        key: stats.key.clone(),
        version: stats.version.clone(),
        enabled: false,
        updated_at_ns: observed_at_ns,
        reason: Some(format!(
            "auto_deactivated after {} deterministic failures in a row",
            stats.deterministic_failure_streak
        )),
    })
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{StrategyOutcomeKind, StrategyTemplateKey, TemplateVersion};

    fn key(template_id: &str) -> StrategyTemplateKey {
        StrategyTemplateKey {
            protocol: "uniswap-v3".to_string(),
            primitive: "swap_exact_in".to_string(),
            chain_id: 8453,
            template_id: template_id.to_string(),
        }
    }

    fn version() -> TemplateVersion {
        TemplateVersion {
            major: 1,
            minor: 0,
            patch: 0,
        }
    }

    #[test]
    fn record_outcome_updates_confidence_priors_and_ranking() {
        stable::init_storage();
        let key = key("learner-confidence");
        let version = version();

        record_outcome(StrategyOutcomeEvent {
            key: key.clone(),
            version: version.clone(),
            action_id: "swap_exact_in".to_string(),
            outcome: StrategyOutcomeKind::Success,
            tx_hash: Some("0xaaa".to_string()),
            error: None,
            observed_at_ns: 10,
        })
        .expect("success outcome should persist");
        let stats = record_outcome(StrategyOutcomeEvent {
            key,
            version,
            action_id: "swap_exact_in".to_string(),
            outcome: StrategyOutcomeKind::DeterministicFailure,
            tx_hash: Some("0xbbb".to_string()),
            error: Some("slippage exceeded".to_string()),
            observed_at_ns: 11,
        })
        .expect("failure outcome should persist");

        assert_eq!(stats.total_runs, 2);
        assert_eq!(stats.success_runs, 1);
        assert_eq!(stats.deterministic_failures, 1);
        assert_eq!(stats.deterministic_failure_streak, 1);
        assert!(stats.confidence_bps > 0);
        assert!(stats.ranking_score_bps > 0);
        assert!(stats.parameter_priors.slippage_bps >= 100);
        assert!(stats.parameter_priors.gas_buffer_bps >= 120);
    }

    #[test]
    fn deterministic_failure_streak_auto_deactivates_template() {
        stable::init_storage();
        let key = key("learner-autodeactivate");
        let version = version();
        stable::set_strategy_template_activation(TemplateActivationState {
            key: key.clone(),
            version: version.clone(),
            enabled: true,
            updated_at_ns: 1,
            reason: Some("seed".to_string()),
        })
        .expect("activation should seed");

        for idx in 0..AUTO_DEACTIVATE_DETERMINISTIC_STREAK {
            record_outcome(StrategyOutcomeEvent {
                key: key.clone(),
                version: version.clone(),
                action_id: "swap_exact_in".to_string(),
                outcome: StrategyOutcomeKind::DeterministicFailure,
                tx_hash: None,
                error: Some("execution reverted".to_string()),
                observed_at_ns: 100 + u64::from(idx),
            })
            .expect("deterministic failure should record");
        }

        let activation = stable::strategy_template_activation(&key, &version)
            .expect("activation should still exist");
        assert!(!activation.enabled);
        assert!(activation
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("auto_deactivated"));
    }
}
