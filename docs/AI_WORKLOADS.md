# AI workloads on Vecta KMS

The KMS protects AI systems the way it protects any other workload: with
keys, secrets, identity and signatures. It does not inspect prompts or
responses, proxy LLM traffic, or score content (docs/DECISIONS.md,
2026-09-30). Every route below already exists and runs through the route
kernel with its own permission and audit event.

| Need | Use | Routes |
|---|---|---|
| Hold LLM provider and MCP server credentials | `secrets` (type `api_key` or `token`), versioned, rotated, every read audited | `POST /svc/secrets/secrets`, `GET /svc/secrets/secrets/{id}/value`, `POST /svc/secrets/secrets/{id}/rotate` |
| Give agents their own identity instead of shared keys | `workload` identity: register the agent, issue short-lived credentials, exchange them for platform tokens | `POST /svc/workload/workload-identity/registrations`, `.../issue`, `.../token/exchange` |
| Keep sensitive values out of prompts and training sets | `dataprotect` tokenization, format-preserving encryption, masking and redaction, called by the customer's app or AI gateway before the data leaves | `POST /svc/dataprotect/tokenize`, `/detokenize`, `/fpe/encrypt`, `/mask`, `/redact` |
| Encrypt model weights, datasets and vector stores at rest | `dataprotect` field and envelope encryption under keycore keys | see the dataprotect section of [API_REFERENCE.md](API_REFERENCE.md) |
| Prove a model artifact is the one you approved | `signing` blob signatures, verified at load time | `POST /svc/signing/signing/blob`, `POST /svc/signing/signing/verify` |
| Customer-managed keys for cloud AI services (Bedrock, Vertex, Azure OpenAI) | `cloud` BYOK to AWS KMS, Google Cloud KMS and Azure Key Vault; `hyok` to keep the key on premises | see the cloud and hyok sections of [API_REFERENCE.md](API_REFERENCE.md) |

Prompt-injection, toxicity and topic filtering, LLM routing and token
budgets belong in an AI security or API gateway product. The earlier
`ai-gateway` service is a seed in KMS Extension
(`seeds/services/ai-gateway`).
