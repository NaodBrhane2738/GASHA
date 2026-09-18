## Pull Request Description

### Summary
*Provide a concise summary of the changes proposed in this PR.*

---

### Team Ownership & Scope
Please indicate the primary engineering area owning this change:
- [ ] Backend API & Graph Engines (`apps/api/app/`)
- [ ] AI & Security Intelligence (`apps/api/app/ai/`, `docs/ai/`)
- [ ] Frontend Web Dashboard (`apps/web/`)
- [ ] Cybersecurity & Detection Rules (`packages/detection-rules/`, `docs/cybersecurity/`)
- [ ] Shared Contracts & SDKs (`packages/contracts/`, `packages/telemetry-sdk/`, `packages/ui/`)
- [ ] Demo Target Application (`apps/demo-target/`)
- [ ] DevOps & Infrastructure (`infra/`, `scripts/`, `.github/`)

---

### Key Questions for Reviewers
1. **Role / Ownership**: Is the code placed in the correct workspace/folder?
2. **Contracts**: Does this change maintain alignment with `@gasha/contracts`?
3. **Evidence Grounding**: If this modifies AI logic, is it strictly grounded on evidence?
4. **Safety**: Are all response actions allowlisted?

---

### Verification & Testing
Describe how this change was validated:
- [ ] Typecheck passing (`pnpm test:contracts`)
- [ ] Backend unit tests passing
- [ ] UI manual verification (screenshots attached)
