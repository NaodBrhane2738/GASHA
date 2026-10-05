# GASHA — Defensive Recommendations Prompt Specification

## Overview
The Defensive Recommendations Prompt constrains the model to emit only allowlisted containment actions (`BLOCK_SOURCE`, `DISABLE_SESSION`, `ISOLATE_RESOURCE`) backed by grounded evidence.

## Core Rules
1. **Allowlist Exclusivity:** Prohibits shell, script, or unapproved actions.
2. **Minimum Necessary Action:** Restricts output to 1-2 focused, high-confidence mitigations.
3. **Evidence Citations:** Links each action to concrete evidence IDs.
4. **Advisory Boundary:** Actions require explicit human operator approval.
