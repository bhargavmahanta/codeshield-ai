# CodeShield Engine

Python security engine for CodeShield AI. Version 0.4.0 provides context-aware
classification, staged Git protection, provider-aware LLM preflight, protected
output, and encrypted local pseudonymization.

```powershell
python -m pip install -e ".[dev]"
python -m pytest tests
codeshield scan .
codeshield policy validate ../policies/default.yaml
codeshield protect input.txt --mode type_placeholder --output protected.txt
codeshield provider verify
codeshield prompt assess --provider openai-api-zdr --file prompt.txt
codeshield evaluate-context
codeshield server
```
