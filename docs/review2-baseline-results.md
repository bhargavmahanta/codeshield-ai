# Review 2 baseline and regex results

Working directory for commands: `engine/`. All pytest runs used a unique
`--basetemp`, disabled repository addopts, and disabled the cache provider.

## Controlled-date repair

- RED: `..\.venv312\Scripts\python.exe -m pytest tests/test_cli.py::test_check_staged_exception_warns_but_returns_success tests/test_cli.py::test_provider_attest_cli_records_only_hashes tests/test_cli.py::test_prompt_protect_pseudonymizes_file_with_local_attestation tests/test_api.py::test_llm_protect_returns_only_pseudonymized_personal_data --basetemp=C:\Users\bharg\AppData\Local\Temp\codeshield-review2-date-red-019f753e -o addopts='' -p no:cacheprovider -q`
  - Result: 4 failed as expected because the fixed review fixtures were stale
    relative to the real 2026-09-06 clock.
- GREEN: `..\.venv312\Scripts\python.exe -m pytest tests/test_cli.py::test_check_staged_exception_warns_but_returns_success tests/test_cli.py::test_provider_attest_cli_records_only_hashes tests/test_cli.py::test_prompt_protect_pseudonymizes_file_with_local_attestation tests/test_api.py::test_llm_protect_returns_only_pseudonymized_personal_data --basetemp=C:\Users\bharg\AppData\Local\Temp\codeshield-review2-date-green-019f753e -o addopts='' -p no:cacheprovider -q`
  - Result: 4 passed, 1 pre-existing deprecation warning.

The tests now scope `date.today()` to 2026-08-01 in the CLI, provider registry,
and policy engine modules. Production expiry policy and fixture expiry dates are
unchanged.

## Generic prefixed credential assignment

- RED: `..\.venv312\Scripts\python.exe -m pytest tests/test_regex_detector.py::test_regex_detector_detects_prefixed_credential_assignment_value_span tests/test_regex_detector.py::test_regex_detector_ignores_noncredential_prefixed_assignments --basetemp=C:\Users\bharg\AppData\Local\Temp\codeshield-review2-regex-red-019f753e -o addopts='' -p no:cacheprovider -q`
  - Result: the new positive case failed with zero findings; all 3 negative
    parameters passed.
- GREEN: `..\.venv312\Scripts\python.exe -m pytest tests/test_regex_detector.py --basetemp=C:\Users\bharg\AppData\Local\Temp\codeshield-review2-regex-green-019f753e -o addopts='' -p no:cacheprovider -q`
  - Result: 6 passed.

The assignment rule now accepts generic identifier segments before supported
credential field names. The captured finding remains the exact assigned value,
and the regression requires a single API-key finding for that value.

## Relevant 116-case baseline

Command: `..\.venv312\Scripts\python.exe -m pytest tests/test_llm_preflight.py tests/test_llm_classification.py tests/test_provider_registry.py tests/test_context_classifier.py tests/test_policy_engine.py tests/test_policy_exceptions.py tests/test_protection.py tests/test_vault.py tests/test_cli.py tests/test_api.py tests/test_proxy.py --basetemp=C:\Users\bharg\AppData\Local\Temp\codeshield-review2-baseline-019f753e -o addopts='' -p no:cacheprovider -q`

Result: 115 passed, 1 skipped, 1 pre-existing Starlette/httpx deprecation
warning; exit code 0.

An earlier reproduction using an engine-local basetemp was blocked by Windows
permissions before test setup (4 errors). It was replaced with the isolated OS
temp paths shown above.
