#![allow(dead_code)]

use crate::domain::types::{
    OperationFailureKind, OutcallFailureKind, RecoveryContext, RecoveryDecision,
    RecoveryDecisionReason, RecoveryFailure, RecoveryPolicyAction, ResponseLimitAdjustment,
    ResponseLimitPolicy,
};

pub fn decide_recovery_action(
    failure: &RecoveryFailure,
    context: &RecoveryContext,
) -> RecoveryDecision {
    match failure {
        RecoveryFailure::Outcall(outcall) => match outcall.kind {
            OutcallFailureKind::ResponseTooLarge => {
                if let Some(response_limit) = context.response_limit.as_ref() {
                    if let Some(adjustment) = next_response_limit_adjustment(response_limit) {
                        return RecoveryDecision {
                            action: RecoveryPolicyAction::TuneResponseLimit,
                            reason: RecoveryDecisionReason::ResponseTooLarge,
                            backoff_secs: None,
                            response_limit_adjustment: Some(adjustment),
                        };
                    }
                }
                backoff_decision(
                    context,
                    outcall.retry_after_secs,
                    RecoveryDecisionReason::ResponseLimitAlreadyMaxed,
                )
            }
            OutcallFailureKind::Timeout
            | OutcallFailureKind::Transport
            | OutcallFailureKind::UpstreamUnavailable => {
                if context.consecutive_failures == 0 {
                    RecoveryDecision {
                        action: RecoveryPolicyAction::RetryImmediate,
                        reason: RecoveryDecisionReason::TransientOutcallFailure,
                        backoff_secs: None,
                        response_limit_adjustment: None,
                    }
                } else {
                    backoff_decision(
                        context,
                        outcall.retry_after_secs,
                        RecoveryDecisionReason::TransientOutcallFailure,
                    )
                }
            }
            OutcallFailureKind::RateLimited => backoff_decision(
                context,
                outcall.retry_after_secs,
                RecoveryDecisionReason::OutcallRateLimited,
            ),
            OutcallFailureKind::InvalidRequest | OutcallFailureKind::RejectedByPolicy => {
                RecoveryDecision {
                    action: RecoveryPolicyAction::EscalateFault,
                    reason: RecoveryDecisionReason::NonRetriableOutcallFailure,
                    backoff_secs: None,
                    response_limit_adjustment: None,
                }
            }
            OutcallFailureKind::InvalidResponse | OutcallFailureKind::Unknown => backoff_decision(
                context,
                outcall.retry_after_secs,
                RecoveryDecisionReason::UnknownFailure,
            ),
        },
        RecoveryFailure::Operation(operation) => match operation.kind {
            OperationFailureKind::BlockedBySurvivalPolicy => RecoveryDecision {
                action: RecoveryPolicyAction::Skip,
                reason: RecoveryDecisionReason::SurvivalPolicyBlocked,
                backoff_secs: None,
                response_limit_adjustment: None,
            },
            OperationFailureKind::InsufficientCycles => RecoveryDecision {
                action: RecoveryPolicyAction::Skip,
                reason: RecoveryDecisionReason::InsufficientCycles,
                backoff_secs: None,
                response_limit_adjustment: None,
            },
            OperationFailureKind::MissingConfiguration
            | OperationFailureKind::InvalidConfiguration
            | OperationFailureKind::Unauthorized
            | OperationFailureKind::Deterministic => RecoveryDecision {
                action: RecoveryPolicyAction::EscalateFault,
                reason: RecoveryDecisionReason::NonRetriableOperationFailure,
                backoff_secs: None,
                response_limit_adjustment: None,
            },
            OperationFailureKind::Unknown => {
                backoff_decision(context, None, RecoveryDecisionReason::UnknownFailure)
            }
        },
    }
}

fn backoff_decision(
    context: &RecoveryContext,
    retry_after_secs: Option<u64>,
    reason: RecoveryDecisionReason,
) -> RecoveryDecision {
    let bounded_max = context.backoff_max_secs.max(1);
    let computed = exponential_backoff_secs(
        context.backoff_base_secs,
        bounded_max,
        context.consecutive_failures,
    );
    let backoff_secs = retry_after_secs.unwrap_or(computed).clamp(1, bounded_max);
    RecoveryDecision {
        action: RecoveryPolicyAction::Backoff,
        reason,
        backoff_secs: Some(backoff_secs),
        response_limit_adjustment: None,
    }
}

fn exponential_backoff_secs(base_secs: u64, max_secs: u64, consecutive_failures: u32) -> u64 {
    let bounded_max = max_secs.max(1);
    let bounded_base = base_secs.clamp(1, bounded_max);
    let shift = consecutive_failures.min(20);
    let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    bounded_base.saturating_mul(multiplier).min(bounded_max)
}

fn next_response_limit_adjustment(
    response_limit: &ResponseLimitPolicy,
) -> Option<ResponseLimitAdjustment> {
    let min_bytes = response_limit.min_bytes.max(1);
    let max_bytes = response_limit.max_bytes.max(min_bytes);
    let from_bytes = response_limit.current_bytes.clamp(min_bytes, max_bytes);
    let multiplier = response_limit.tune_multiplier.max(2);
    let to_bytes = from_bytes
        .saturating_mul(multiplier)
        .clamp(min_bytes, max_bytes);
    (to_bytes > from_bytes).then_some(ResponseLimitAdjustment {
        from_bytes,
        to_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::decide_recovery_action;
    use crate::domain::types::{
        OperationFailure, OperationFailureKind, OutcallFailure, OutcallFailureKind,
        RecoveryContext, RecoveryDecisionReason, RecoveryFailure, RecoveryPolicyAction,
        ResponseLimitPolicy,
    };

    fn base_context() -> RecoveryContext {
        RecoveryContext {
            backoff_base_secs: 5,
            backoff_max_secs: 120,
            ..RecoveryContext::default()
        }
    }

    #[test]
    fn response_too_large_tunes_response_limit_when_headroom_exists() {
        let context = RecoveryContext {
            response_limit: Some(ResponseLimitPolicy {
                current_bytes: 256,
                min_bytes: 256,
                max_bytes: 4096,
                tune_multiplier: 2,
            }),
            ..base_context()
        };

        let decision = decide_recovery_action(
            &RecoveryFailure::Outcall(OutcallFailure {
                kind: OutcallFailureKind::ResponseTooLarge,
                retry_after_secs: None,
                observed_response_bytes: Some(400),
            }),
            &context,
        );

        assert_eq!(decision.action, RecoveryPolicyAction::TuneResponseLimit);
        assert_eq!(decision.reason, RecoveryDecisionReason::ResponseTooLarge);
        assert_eq!(
            decision.response_limit_adjustment,
            Some(crate::domain::types::ResponseLimitAdjustment {
                from_bytes: 256,
                to_bytes: 512
            })
        );
    }

    #[test]
    fn response_too_large_without_headroom_falls_back_with_backoff() {
        let context = RecoveryContext {
            response_limit: Some(ResponseLimitPolicy {
                current_bytes: 4096,
                min_bytes: 256,
                max_bytes: 4096,
                tune_multiplier: 2,
            }),
            ..base_context()
        };

        let decision = decide_recovery_action(
            &RecoveryFailure::Outcall(OutcallFailure {
                kind: OutcallFailureKind::ResponseTooLarge,
                retry_after_secs: None,
                observed_response_bytes: None,
            }),
            &context,
        );

        assert_eq!(decision.action, RecoveryPolicyAction::Backoff);
        assert_eq!(
            decision.reason,
            RecoveryDecisionReason::ResponseLimitAlreadyMaxed
        );
        assert_eq!(decision.backoff_secs, Some(5));
    }

    #[test]
    fn transient_outcall_failure_retries_immediately_on_first_failure() {
        let decision = decide_recovery_action(
            &RecoveryFailure::Outcall(OutcallFailure {
                kind: OutcallFailureKind::Transport,
                retry_after_secs: None,
                observed_response_bytes: None,
            }),
            &base_context(),
        );
        assert_eq!(decision.action, RecoveryPolicyAction::RetryImmediate);
        assert_eq!(
            decision.reason,
            RecoveryDecisionReason::TransientOutcallFailure
        );
    }

    #[test]
    fn transient_outcall_failure_uses_exponential_backoff_after_retries() {
        let context = RecoveryContext {
            consecutive_failures: 4,
            ..base_context()
        };
        let decision = decide_recovery_action(
            &RecoveryFailure::Outcall(OutcallFailure {
                kind: OutcallFailureKind::Timeout,
                retry_after_secs: None,
                observed_response_bytes: None,
            }),
            &context,
        );
        assert_eq!(decision.action, RecoveryPolicyAction::Backoff);
        assert_eq!(decision.backoff_secs, Some(80));
    }

    #[test]
    fn rate_limited_outcall_honors_retry_after_hint_with_bounds() {
        let context = RecoveryContext {
            backoff_max_secs: 120,
            ..base_context()
        };
        let decision = decide_recovery_action(
            &RecoveryFailure::Outcall(OutcallFailure {
                kind: OutcallFailureKind::RateLimited,
                retry_after_secs: Some(600),
                observed_response_bytes: None,
            }),
            &context,
        );
        assert_eq!(decision.action, RecoveryPolicyAction::Backoff);
        assert_eq!(decision.reason, RecoveryDecisionReason::OutcallRateLimited);
        assert_eq!(decision.backoff_secs, Some(120));
    }

    #[test]
    fn survival_policy_blocked_operation_is_skipped() {
        let decision = decide_recovery_action(
            &RecoveryFailure::Operation(OperationFailure {
                kind: OperationFailureKind::BlockedBySurvivalPolicy,
            }),
            &base_context(),
        );
        assert_eq!(decision.action, RecoveryPolicyAction::Skip);
        assert_eq!(
            decision.reason,
            RecoveryDecisionReason::SurvivalPolicyBlocked
        );
    }

    #[test]
    fn invalid_configuration_escalates_fault() {
        let decision = decide_recovery_action(
            &RecoveryFailure::Operation(OperationFailure {
                kind: OperationFailureKind::InvalidConfiguration,
            }),
            &base_context(),
        );
        assert_eq!(decision.action, RecoveryPolicyAction::EscalateFault);
        assert_eq!(
            decision.reason,
            RecoveryDecisionReason::NonRetriableOperationFailure
        );
    }
}
