# orchestrator/state/*.json — schema (v2)

Rule: schemas are backward-compatible. Only ADD fields. Every number shown in README/frontend/advisories/PITCH_NOTES must come from these files.

## attack_result.json
- `patterns[]`: existing fields + per confirmed exploit:
  - `economics`: `{pool_balance_before, donation, deposit, minted_usd, attacker_cost_usd, attacker_net_usd, roi, bad_debt_usd, profitable(bool), profit_condition(str)}`
  - `irrational_reference`: `{donation, deposit, attacker_net_usd}` — the old (unprofitable) params, for honesty
- Vuln B pattern: `result="MISPRICING_FINDING"`, `attacker_profit_usd=0`, `depositor_loss_usd=<gap>` (never a headline attack impact)

## validation.json  (per-version)
- `{ "v1": {...}, "v2": {...} }`
- v1: `basis_label="VACUOUS_FOR_RATE_DELTAS"`, `reason`, plus existing fields
- v2: `{basis_label="measured_conversion_ratio", applicable_traces_checked, max_observed_bps, threshold_bps, threshold_basis, false_positives, tier2_stress:[{scenario, v1_fp, v2_fp}]}`

## guard_report.json  (per-version)
- `{ "v1": {...}, "v2": {...} }` each: `{version, guard_class, scope("wrapper"|"chokepoint"), reattack_reverts(bool), gas_plain_deposit, gas_guarded_deposit, gas_overhead, gas_overhead_pct, gas_depositAndMint*, evidence_test}`

## bypass_report.json  (per-version)
- `{version, strategies:[{name, verdict("BYPASSED"|"BLOCKED"|"ERROR"|"NOT_APPLICABLE"), evidence_test, reason, mitigation}], n_bypassed, n_blocked, n_error, residual_risks:[{name, max_extractable_usd, note}]}`
- Verdicts come ONLY from executed forge tests. No hardcoded strings.

## state.json  (frontend)
- `iterations[]`: `{version, guard_class, scope, threshold_basis, validation_summary, n_bypassed, strategies:[{name, verdict}]}`
- plus existing attacker/defender blocks (kept)
