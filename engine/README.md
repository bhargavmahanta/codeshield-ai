# CodeShield Engine

Python security engine for CodeShield AI. Version 0.5.0 adds optional local
Presidio/spaCy and Gitleaks detection, deterministic evaluation, staged Git
protection, provider-aware LLM preflight, and encrypted pseudonymization.

```powershell
python -m pip install -e ".[dev]"
python -m pytest tests
codeshield scan .
codeshield policy validate ../policies/default.yaml
codeshield protect input.txt --mode type_placeholder --output protected.txt
codeshield provider verify
codeshield prompt assess --provider openai-api-zdr --file prompt.txt
codeshield evaluate-context
codeshield detector status
codeshield evaluate prepare --suite phase5
codeshield evaluate run --profile core --output ../reports/local-core.json
codeshield server
```

Install the larger enhanced/evaluation profile explicitly:

```powershell
python -m pip install -e ".[dev,enhanced,evaluation]"
$env:PATH="$PWD\..\.tools\gitleaks;$env:PATH"
codeshield evaluate run --profile enhanced --output ../reports/local-enhanced.json
```
