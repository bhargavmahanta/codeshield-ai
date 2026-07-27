# CodeShield Engine

Python security engine for CodeShield AI. Version 0.6.0 adds secure SARIF,
static fragment reconstruction, read-only interoperability APIs, and
cross-platform release hardening.

```powershell
python -m pip install -e ".[dev]"
python -m pytest tests
codeshield scan .
codeshield scan . --format sarif --output ../codeshield.sarif
codeshield policy validate ../policies/default.yaml
codeshield protect input.txt --mode type_placeholder --output protected.txt
codeshield provider verify
codeshield prompt assess --provider openai-api-zdr --file prompt.txt
codeshield evaluate-context
codeshield detector status
codeshield evaluate prepare --suite phase5
codeshield evaluate run --profile core --output ../reports/local-core.json
codeshield evaluate run --suite phase6 --profile core --output ../reports/local-phase6.json
codeshield server
```

Install the larger enhanced/evaluation profile explicitly:

```powershell
python -m pip install -e ".[dev,enhanced,evaluation]"
$env:PATH="$PWD\..\.tools\gitleaks;$env:PATH"
codeshield evaluate run --profile enhanced --output ../reports/local-enhanced.json
```
