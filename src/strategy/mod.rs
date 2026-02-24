/// Strategy subsystem — intent compilation, ABI normalisation, outcome learning, and validation.
///
/// The subsystem is divided into five focused modules that form a pipeline:
///
/// 1. [`abi`]       — normalise raw Solidity ABI JSON into canonical [`AbiArtifact`]s and
///    recompute / verify 4-byte function selectors.
/// 2. [`compiler`]  — compile a [`StrategyExecutionIntent`] into a fully-encoded [`ExecutionPlan`]
///    (ABI-encoded calldata per call).
/// 3. [`registry`]  — thin persistence façade over `storage::stable`; stores and retrieves
///    strategy templates, ABI artifacts, activation/revocation/kill-switch state,
///    and outcome stats.
/// 4. [`learner`]   — accumulate execution outcome events and derive confidence, ranking, and
///    parameter-prior estimates; auto-deactivates templates on repeated
///    deterministic failures.
/// 5. [`validator`] — multi-layer gate that checks schema correctness, address consistency,
///    policy constraints, EVM preflight simulation, and postcondition presence
///    before a plan is submitted on-chain.
///
/// [`AbiArtifact`]: crate::domain::types::AbiArtifact
/// [`StrategyExecutionIntent`]: crate::domain::types::StrategyExecutionIntent
/// [`ExecutionPlan`]: crate::domain::types::ExecutionPlan
pub mod abi;
pub mod compiler;
pub mod learner;
pub mod registry;
pub mod validator;
