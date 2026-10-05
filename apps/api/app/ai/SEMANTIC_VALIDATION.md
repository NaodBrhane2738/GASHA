# GASHA AI - Semantic Validation Framework

The Final Semantic Hardening task implements deterministic validation for the AI Investigation subsystem, ensuring LLM outputs are rigorously vetted against known security evidence. The framework relies on 10 core semantic rules:

## 1. Identifier Grounding
All identifiers (IPs, sessions, assets, users) used by the AI in text fields (summaries, rationales) must map back to explicit identifiers present in the input telemetry and evidence context. Any deviation triggers an `INVALID_IDENTIFIER` warning.

## 2. Attack Phase Vocabulary
AI-generated attack stages must use the predefined GASHA MITRE-based phase list (e.g., `INITIAL_ACCESS`, `PRIVILEGE_ESCALATION`, `EXFILTRATION`). Invented phases like `COMMAND_AND_CONTROL` are deterministically normalized or rejected.

## 3. Attempt vs. Confirmed Compromise
The AI cannot claim a confirmed compromise (e.g., `PRIVILEGE_ESCALATION`) without concrete evidence of success (e.g., `status: 200`, `success`, `admin_role`). Hostile probes or denied actions are explicitly downgraded to attempts.

## 4. Conflict Handling
The `detect_evidence_conflicts` logic identifies contradictory telemetry (e.g., DB logs reporting `denied` while App logs report `success` for the same entity) and injects explicit uncertainties into the investigation unknowns. 

## 5. Contextual Recommendation Validation
Defensive recommendations must make contextual sense. For example, `ISOLATE_RESOURCE` is rejected if there is an approved maintenance window and no verified deviation. `BLOCK_SOURCE` may be flagged as over-broad if a specific session ID is targeted and the IP is shared/mixed.

## 6. Attribution Calibration
Unsupported claims attributing attacks to specific actors without definitive threat-intelligence evidence are strictly calibrated to conservative phrasing. 

## 7. Natural-Language Identifier Validation
A secondary regex-based scan ensures identifiers (IPs, sessions) within free-text generation, such as rationales and progression descriptions, correctly align with the deterministic facts, preventing LLM hallucinations.

## 8. Asset Consistency
Assets listed in `affectedAssetIds` must be present in the original investigation context. Fabrication of non-existent assets (e.g., `web-app-03` when only `-01` and `-02` exist) is rejected.

## 9. Closed-World Evidence Grounding
All evidence IDs cited by the LLM in facts, inferences, or recommendations must precisely match the deterministic `id` references in the context.

## 10. Epistemic Classification
A strict separation of `observedFacts` (directly proven), `inferences` (logically deduced), and `unknowns` (visibility gaps). The AI cannot state an inference as a fact if it lacks direct telemetry.
