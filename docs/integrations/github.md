# GitHub Integration Guide

> **ROLE / OWNERSHIP**: DevOps & Backend Engineers  
> **OBJECTIVE**: Detail GitHub App permissions, Octokit client setup, and dependency graph inspection.

---

## 1. Authentication
Authenticated via GitHub App Installation Tokens or Personal Access Tokens.

## 2. Resources Discovered
- Repositories: Languages, default branch, commits
- Dependency Graph: Scans `package.json`, `requirements.txt`, `poetry.lock` for third-party packages
- Dependabot Alerts: Discovered CVEs and severity ratings
