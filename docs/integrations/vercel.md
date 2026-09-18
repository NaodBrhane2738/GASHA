# Vercel Integration Guide

> **ROLE / OWNERSHIP**: DevOps & Backend Engineers  
> **OBJECTIVE**: Detail Vercel REST API authentication, deployment discovery, and webhook handling.

---

## 1. Authentication
Uses Vercel Personal Access Tokens or OAuth integration tokens passed in `Authorization: Bearer <TOKEN>`.

## 2. Resources Discovered
- Projects: `GET /v9/projects`
- Deployments: `GET /v6/deployments`
- Serverless / Edge Functions: Extracted from deployment build output manifests
- Environment Configurations: Project environment variable keys (values redacted for security)
