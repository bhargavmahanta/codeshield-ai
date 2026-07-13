# CodeShield Engine

Python security engine for CodeShield AI. Version 0.2.0 adds context-aware
classification, YAML destination policies, protected output, and encrypted local
pseudonymization.

```powershell
python -m pip install -e ".[dev]"
python -m pytest tests
codeshield scan .
codeshield policy validate ../policies/default.yaml
codeshield protect input.txt --mode type_placeholder --output protected.txt
codeshield evaluate-context
codeshield server
```
