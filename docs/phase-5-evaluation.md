# Phase 5: Evaluation and Detector Hardening

CodeShield `0.5.0` keeps regex and entropy detection in the dependency-light
`core` profile and adds an explicit `enhanced` profile with local Presidio/spaCy
PII analysis and Gitleaks credential scanning. A requested enhanced scan fails
with exit code `3` when either optional runtime is unavailable; CodeShield does
not silently fall back to core.

## Detector Safety

- Presidio Analyzer is pinned to `2.2.363`, spaCy to the `3.8` line, and
  `en_core_web_sm` to `3.8.0` with wheel SHA-256 verification. Loading is lazy and tldextract uses its bundled
  public-suffix snapshot, so analysis does not require a network call.
- A deterministic candidate-line prefilter avoids running NER over ordinary
  source boilerplate. Candidate findings retain exact document offsets.
- Gitleaks is pinned to `8.30.1` with archive SHA-256 verification, receives content through stdin, uses
  `shell=False`, and accepts only exit codes `0` and `1`.
- Gitleaks writes to a private temporary JSON report. Raw `Secret` and `Match`
  fields are discarded in memory, the report is removed in `finally`, and
  errors never include subprocess output or scanned content.
- Overlap priority is Gitleaks, regex, Presidio, then entropy after severity,
  confidence, and category specificity.

## Dataset And Licensing

The versioned manifest is
[`engine/codeshield/evaluation/manifest.yaml`](../engine/codeshield/evaluation/manifest.yaml).
It records the suite version, seed, source, license, file inventory, entity
mapping, and SHA-256 digest. Preparation regenerates every file and rejects a
digest mismatch.

The three prepared datasets are:

1. CodeShield deterministic synthetic secrets, negative entropy cases, mixed
   code/PII, Unicode, JSON, and a separately reported split-token adversarial case.
2. Synthetic person/location sentences adapted from the MIT-licensed Microsoft
   Presidio Research template methodology (`0.2.5`), without copying personal data.
3. Synthetic Git/LLM policy, transformation, inbound-response, and privileged-tool
   workflows.

Generated data lives outside Git under `CODESHIELD_DATA_HOME`. SecretBench,
real secrets, real PII, provider validation calls, and AI4Privacy data are not
used in Phase 5.

## Metrics And Gates

Reports contain aggregate counts and versions only: exact-span and relaxed
precision/recall/F1/F2, per-category and per-source scores, negative-suite FPR,
context macro metrics/confusion matrix, policy and restricted-transfer blocking,
transformation/restoration safety, and cold/warm latency at 1, 10, and 100 KB.
They contain no input text, findings, masked previews, raw paths, or reversible
mappings.

The committed Windows baseline records core macro F2 `1.00`, core negative FPR
`0.00`, context macro F1 `0.9881`, enhanced synthetic PII recall `1.00`, and
enhanced 100 KB warm p95 `781.61 ms`. These are deterministic synthetic-suite
engineering results, not claims of real-world detector accuracy.

CI enforces mandatory security outcomes at `100%`, core macro F2 at least
`0.90`, core FPR at most `0.05`, context macro F1 at least `0.90`, enhanced PII
recall improvement of at least `0.10`, no overall F2 regression above `0.02`,
core 100 KB p95 at most `250 ms`, and enhanced p95 at most `3 s`.

## Reproduce On Windows

```powershell
cd E:\Projects\codeshield-ai
$env:CODESHIELD_DATA_HOME="$PWD\.phase5-data"

.\.venv312\Scripts\python.exe -m pip install -e ".\engine[dev,evaluation]"
.\.venv312\Scripts\codeshield.exe evaluate prepare --suite phase5
.\.venv312\Scripts\codeshield.exe evaluate run --profile core --output .phase5-core.json
.\.venv312\Scripts\codeshield.exe evaluate compare reports\phase5\core-baseline.json .phase5-core.json
```

For enhanced evaluation, install the enhanced extras and put the verified
Gitleaks `8.30.1` executable on `PATH`:

```powershell
.\.venv312\Scripts\python.exe -m pip install -e ".\engine[dev,enhanced,evaluation]"
$env:PATH="$PWD\.tools\gitleaks;$env:PATH"
.\.venv312\Scripts\codeshield.exe detector status
.\.venv312\Scripts\codeshield.exe evaluate run --profile enhanced --output .phase5-enhanced.json
.\.venv312\Scripts\codeshield.exe evaluate compare reports\phase5\core-baseline.json .phase5-enhanced.json
```

## Reproduce With Docker

```powershell
docker compose --profile evaluation build evaluation
docker compose --profile evaluation run --rm evaluation
```

The normal engine image remains core-only. The evaluation image separately
contains the pinned model and Gitleaks runtime and writes only aggregate reports
to `reports/phase5`.

## Limitations

- Synthetic scores do not estimate production precision or recall.
- The English small spaCy model has language and entity-recognition limits.
- Candidate prefiltering improves code latency but can miss unconventional PII
  phrasing; the adversarial split-token miss remains visible in the report.
- Secure deletion cannot be guaranteed on every filesystem; temporary reports
  are access-restricted, short-lived, and removed immediately.
- Enhanced scanning increases installation size and runtime, so core remains the
  default profile.
