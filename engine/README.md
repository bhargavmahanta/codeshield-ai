# CodeShield Engine

Python security engine for CodeShield AI. Version 0.7.0 adds bounded stdin
editor interoperability and safe relative-path JSON output while preserving
the Phase 6 SARIF, fragment detection, and cross-platform hardening.

```powershell
python -m pip install -e ".[dev]"
python -m pytest tests
codeshield scan .
codeshield scan . --format sarif --output ../codeshield.sarif
Get-Content input.py | codeshield scan-text --stdin --source-path input.py --format json
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
