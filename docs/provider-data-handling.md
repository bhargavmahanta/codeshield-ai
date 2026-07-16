# LLM Provider Data-Handling Matrix

Reviewed: 2026-07-16

Review due: 2026-10-14
Status: engineering guidance, not a legal or contractual compliance determination

CodeShield profiles products and surfaces rather than assigning one privacy label to an entire company. Account contracts, workspace configuration, model eligibility, and enabled features can materially change retention even when the model name is unchanged. The machine-readable source is `engine/codeshield/providers/profiles.yaml`.

## Normalized Data Types

Provider terms are mapped to these CodeShield concepts: prompt, output, uploaded file, code/workspace context, application state, cache, abuse log, fine-tuning data, feedback, telemetry, connector data, and account metadata.

## Comparison

| Provider surface | Training use | Conservative retention used by CodeShield | Important exceptions | Confidential code default |
| --- | --- | ---: | --- | --- |
| OpenAI API standard | No training by default | 30 days | Stateful endpoints, files, application state, cache, and code execution can store data | Attestation required; incompatible features blocked |
| OpenAI API approved ZDR | No training | 0 days for eligible use | Endpoint eligibility, safety retention, files, and stateful capabilities remain material | Allowed after exact-profile attestation |
| ChatGPT Enterprise | No training | 30-day configured baseline | Workspace retention, connectors, files, and code execution | Allowed only with attested workspace controls |
| Anthropic API commercial | No training without permission | 30-day conservative model bound | Covered models and retained features differ | Attestation required |
| Anthropic API/Claude Code ZDR | No training | 0 days for eligible features | Console, consumer products, files, code execution, metrics, and some models are excluded | Allowed after exact-profile attestation |
| Gemini Developer API paid | No training | 30 days | Grounding, interactions storage, Live resumption, files, and explicit cache | Attestation required; named features blocked |
| Gemini/Vertex approved ZDR | No training | 0 days for eligible configuration | Grounding, state, files, cache, and abuse-monitoring eligibility | Allowed after exact-profile attestation |
| Azure Foundry stateless inference | No base-model training | 30-day conservative abuse bound | Responses, Assistants, stored completions, files, and global processing differ | Attestation required; stateful features blocked |
| Amazon Bedrock runtime | No provider access or model training from prompts | 30-day conservative abuse bound | AWS configuration, logs, agents, knowledge bases, and free-form metadata remain customer responsibilities | Attestation required |
| GitHub Copilot Business/Enterprise IDE | No organization interaction training | Prompts and suggestions not retained by default | Workspace context is transmitted; feedback and engagement metadata have separate retention | Allowed after organization attestation |
| GitHub Copilot Business CLI/GitHub.com | No organization interaction training | 28 days | Thread history and non-IDE surfaces retain prompts/suggestions | Attestation required; stateful mode must be declared |
| Consumer/individual products | Provider and setting dependent | Unbounded/unknown | Training opt-outs, chat history, files, connectors, and coding context vary | Reference only; non-public content blocked |

## Primary Sources

- [OpenAI API data controls](https://developers.openai.com/api/docs/guides/your-data)
- [OpenAI business data privacy](https://openai.com/business-data/)
- [Anthropic API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention)
- [Gemini Developer API zero data retention](https://ai.google.dev/gemini-api/docs/zdr)
- [Vertex AI zero data retention](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/vertex-ai-zero-data-retention)
- [Azure Foundry data privacy and security](https://learn.microsoft.com/en-us/azure/foundry/responsible-ai/openai/data-privacy)
- [Amazon Bedrock data protection](https://docs.aws.amazon.com/bedrock/latest/userguide/data-protection.html)
- [GitHub Copilot data handling](https://github.com/features/copilot)

## Evidence Rules

Profiles are reviewed facts, not proof of an account's configuration. Before non-public content is allowed, a local attestation must identify the exact profile version, contain only an opaque account hash and evidence digest, list reviewed controls, and expire no later than the profile. Both profile and attestation windows are at most 90 days. Stale, unknown, mismatched, or missing evidence fails closed.

Provider changes must be researched from first-party documentation. Update the reviewed date, due date, evidence links, feature exceptions, and tests together. CI deliberately fails when the review date expires.
