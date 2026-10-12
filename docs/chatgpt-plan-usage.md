# Using a ChatGPT plan for HorusScan enrichment (experimental)

This provider is intended for locally operated, open-source HorusScan. It
requires **explicit user sign-in and consent**. It does not use OpenAI API keys
or share browser-session cookies.

## Install

```sh
pip install -e '.[chatgpt]'
horustrace chatgpt login
```

The login command starts a listener on `127.0.0.1` with path
`/auth/callback` and opens the system browser. Review the permissions
and authorize **HorusScan** through the official OpenAI sign-in page.
The CLI validates the issuer's JWKS-signed ID token, OIDC nonce, OAuth state,
PKCE verifier and issued dynamic client ID before saving any credential.

The host identity and per-account access, refresh and ID tokens are stored in
`~/.config/horustrace/chatgpt/` using atomic local owner-only credential files
(0600 on Unix). Never copy these files into GitHub Secrets, repositories,
managed CI runners, browser storage, cloud support tickets or chats.

The model used by the scanner must be selected from your account's catalog:

```sh
horustrace chatgpt accounts
horustrace chatgpt models
horustrace scan ./my-agent-repository \
  --semantic-llm-provider chatgpt_plan \
  --semantic-llm-model '<slug from chatgpt models>' \
  --semantic-llm-max-candidates 3 \
  --format json
```

The usual semantic candidate budget, source provenance and deterministic
rule/path engine remain unchanged. The inference transport sends
`store=false`, `stream=true` to the public Responses API and requires
`response.completed` before accepting results.

For multiple saved account registrations:

```sh
horustrace chatgpt accounts
horustrace chatgpt login --account '<saved account ID>'
horustrace chatgpt models --account '<saved account ID>'
# For scan selection, use a local environment variable containing the
# account *identifier*, never a token:
HORUSTRACE_CHATGPT_ACCOUNT='<saved account ID>' \
  horustrace scan . --semantic-llm-provider chatgpt_plan \
  --semantic-llm-model '<account-specific model slug>'
```

Register an additional account using `horustrace chatgpt login --new`.
To revoke a session, run `horustrace chatgpt logout [--account ID]`.
If remote revocation is not confirmed, the CLI reports this honestly and
clears local tokens; disconnect the application in ChatGPT Settings.

## Existing and new cohort studies

A local sign-in is **not** an authorization to run arbitrary model requests
using that plan from a standard GitHub-hosted Actions runner. HorusScan must
execute the authorized requests on the user's local runtime or a supported
remote VM under that same user's control. For VMs the OpenAI guide requires
a local OAuth flow first, secure credential transfer and a VM-specific host ID.

The Fresh-16 pinned scanner cohort lives in
`research/fresh-unseen-generalization-20/cohort.json`; the paired comparison
harness is in PR #526. Running an actual ChatGPT-plan-backed cohort requires
user authorization on the scan runtime. The experimental provider currently
has only offline authentication/transport tests; there are **no verified
live plan inferences or measured accuracy improvements** yet.

Do not silently interpret `fail_open` source scans with LLM request failures
as a successful LLM vs deterministic comparison. The research gate must
fail closed if no model calls succeed or if any model call errors.

## Requirements and limitations

- Eligible ChatGPT account and sufficient shared plan quota; Plus plan usage
  is shared across connected applications.
- `PyJWT[crypto]` optional dependency needed to validate signed identities.
- Browser-initiated OAuth callback at `127.0.0.1` on the same device.
- A POSIX user-controlled runtime for automatic refresh locking in this
  implementation. Windows support requires additional credential-store and
  locking validation before claiming cross-platform readiness.
- The login and inference code is **experimental**, pending security review,
  verified live OAuth consent and model catalog / Responses integration tests.
- The user must explicitly approve sign-in and any ongoing automation.

## Official references

- https://developers.openai.com/siwc/token-sharing-open-source/sign-in
- https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions
- https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference
- https://developers.openai.com/siwc/token-sharing-open-source/self-hosted-vms
- https://openai.com/policies/sign-in-with-chatgpt-terms/
