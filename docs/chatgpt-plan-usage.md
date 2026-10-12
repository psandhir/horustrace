# ChatGPT plan usage in HorusScan — experimental transport

**State: transport proof of concept only. Browser-based sign-in is not yet implemented.**
This branch does **not** grant access to a ChatGPT subscription, authorize a
GitHub-hosted runner, or complete the Fresh-16 hybrid comparison.

## Why

The existing `openai` provider requires a separate OpenAI API key.
The optional `chatgpt_plan` provider uses a user-authorized **Sign in with
ChatGPT** OAuth bearer token instead. It keeps HorusScan's existing bounded
semantic prompts, JSON schemas, provenance checks, candidate budgets, and
deterministic rule/path evaluation.

The transport uses OpenAI's public `POST /v1/responses` endpoint with
`store: false` and `stream: true`; an inference is successful **only**
after `response.completed`. `response.failed`, `response.incomplete`,
network errors, invalid JSON and interrupted streams fail closed at the
transport layer and are counted as scanner semantic failures by existing
fail-open/fail-closed callers.

## Current integration seam (only after legitimate user authorization)

```bash
# Illustrative only. The OAuth login flow is not implemented in this PR.
# Never copy ChatGPT browser cookies or session credentials.
export HORUSTRACE_CHATGPT_ACCESS_TOKEN="<authorized short-lived OAuth access token>"
horustrace scan . --semantic-llm-provider chatgpt_plan \
  --semantic-llm-model "<slug returned by the authorized account's model list>" \
  --format json
```

The account must explicitly approve `resource.invoke` and
`chatgpt.tokens.use.direct`. The correct model slug must be selected from
that account's model catalog. This branch does **not** do either step for you.

No OAuth tokens should be committed, uploaded to CI artifacts or scanner
reports, passed into GitHub Secrets, or shared in chat. Do **not** use the
standard GitHub-hosted Actions runner for SIWC plan usage.

## Required next phase before usable end-to-end

1. Build the documented OAuth 2.0 / OIDC / PKCE dynamic registration with
   `dynamic_agent_client`, stable local host identifier, system browser and
   exact `http://127.0.0.1:<port>/auth/callback` listener.
2. Verify the ID token signature against issuer JWKS, issuer/audience/nonce,
   the callback state, and the granted plan-usage scopes.
3. Keep refresh tokens and identity profiles in protected **user-controlled
   local storage only**; provide account selection, refresh, revoke, logout,
   and explicit permission before any automated or recurring workload.
4. Implement a per-account model listing call to `GET /v1/models`; use the
   account-specific `slug` and first-run preflight.
5. Support user-controlled local or properly configured user-controlled remote
   runtimes, not ordinary managed GitHub Actions for personal SIWC credentials.
6. Execute the original **pinned** Fresh-16 baseline/hybrid cohort once the
   user completes sign-in; independently adjudicate all graph and finding deltas.

## Reference documentation

- https://developers.openai.com/siwc/token-sharing-open-source/sign-in
- https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference
- https://developers.openai.com/siwc/token-sharing-open-source/self-hosted-vms
- https://openai.com/policies/sign-in-with-chatgpt-terms/

HorusScan must not request ChatGPT account passwords, browser session cookies,
unofficial ChatGPT backend endpoints, or credentials submitted in pull-request
comments. Usage limits and personal ChatGPT plan eligibility apply.
