# Review 3 Package

This directory contains the CodeShield AI Review 3 report, built on the
institution's Project Review template.

## Deliverables

- `CodeShield_AI_Review_3.docx`: editable report (project snapshot, team and
  project journey, chapters 1–11, references, source-code appendix).
- `CodeShield_AI_Review_3.pdf`: PDF export of the report. It still shows the
  identity placeholders; export it again from Word after completing them.
- `Project_Review_Template.docx`: the institution's blank Project Review
  template the report was built on.

## Evidence used

- Technical content comes from the root `README.md`, the `docs/phase-*.md`
  documents, the Review 1 package, and the Review 2 records.
- Metrics come from the committed `reports/phase9` core and enhanced baselines.
  The context-classifier result (macro F1 `0.9881`) was reproduced on
  2026-10-22 with `codeshield evaluate-context`.
- Figures 4–6 are renderings of real CLI output captured on 2026-10-22 with
  CodeShield `0.9.0` and Python `3.12.10`, using unmistakably synthetic values
  in a throwaway repository.

## Test-suite status recorded in the report

On 2026-10-22, `python -m pytest engine/tests` (Windows 11, Python 3.12.10)
gave **231 passed, 21 failed, 6 skipped**. All 21 failures are
provider-dependent (19 proxy tests, one API metadata test, one provider CLI
test). They coincide with the provider-evidence `review_due` date of
2026-10-14: 20 of the 21 profiles in
`engine/codeshield/providers/profiles.yaml` are now reported stale, so the
proxy fails closed as designed. The evidence needs a real re-review; extending
the dates without one would defeat the control.

## Editable identity fields

Placeholders shown in red in the report must be completed before submission:
course code and title, Internship/Dissertation, class ID, review date,
register number (cover, work table, footer), demo video URL and duration,
skills already known, Review 1 and 2 feedback and actions, the Review 2 date,
and the patent, publication, startup, and other-plan outcome rows.
