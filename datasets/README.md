# Datasets

Phase 5 commits only the manifest, deterministic generators, expected digests,
and aggregate reports. Prepared JSONL files are written under
`CODESHIELD_DATA_HOME` (default `~/.codeshield/datasets`) and never committed.

The suite contains CodeShield-generated synthetic cases and templates adapted
from the MIT-licensed Microsoft Presidio Research methodology. It contains no
SecretBench records, real credentials, real personal data, provider calls, or
license-restricted AI4Privacy data. See
[`docs/phase-5-evaluation.md`](../docs/phase-5-evaluation.md) for methodology and
reproduction commands.
