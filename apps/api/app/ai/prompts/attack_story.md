# GASHA — Attack Story Prompt Specification

## Overview
The Attack Story Prompt guides the model to transform raw forensic evidence into a human-readable, chronological attack progression.

## Core Mandates
1. **XML Boundary Defense:** All context is wrapped inside `<untrusted_security_context>...</untrusted_security_context>`.
2. **Attempt vs Success Distinction:** Never assert compromise or exfiltration without direct proof.
3. **Evidence Citations:** Every stage must link to verified evidence IDs in the context.
4. **Epistemic Honesty:** Explicit uncertainty declaration for unlogged steps.
