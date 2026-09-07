"""Extension-owned terminal labels; no raw finding or subprocess rendering."""

import unicodedata


def escape_terminal(text: str) -> str:
    return "".join(c if c in "\n\t" or not unicodedata.category(c).startswith("C") else f"\\u{ord(c):04x}" for c in text)


def explain_lines(result):
    assessment = result.assessment
    yield f"Sensitivity: {assessment.highest_sensitivity.value.title()}"
    yield "Client: OpenCode; destination: OpenAI ChatGPT Plus/Pro sign-in"
    yield "Provider policy: Public-only subscription route; non-public content denied"
    if result.llm_policy:
        yield f"Mandatory rule: {'YES' if result.llm_policy.mandatory else 'NO'}; action: {result.llm_policy.action.value.upper()}"
    for segment in assessment.segments:
        for finding in segment.findings:
            yield f"Detector: {finding.detection_source.value}; category: {finding.data_category.value}"
            yield f"Detection confidence: {finding.confidence_score:.2f}"
            if finding.context:
                yield "Classifier: " + ("Deterministic context rules" if finding.context.explanation.startswith("Deterministic context signals") else "ML fallback using structural features")
                yield f"Context: {finding.context.label.value}; confidence: {finding.context.confidence:.2f}"
                # Signals originate in the classifier but are allowlisted here.
                allowed = {"placeholder_signal", "production_signal", "sensitive_variable", "under_tests", "under_fixtures", "comment_like"}
                signals = sorted(set(finding.context.signals) & allowed)
                yield "Context signals: " + (", ".join(signals) if signals else "none")
            if finding.risk:
                yield f"Risk score: {finding.risk.score}/100"
            decision = finding.policy_decision
            if decision:
                yield f"Finding-level rule: {'mandatory' if decision.mandatory else 'non-mandatory'}; action: {decision.action.value.upper()}"
