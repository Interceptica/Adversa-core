# Prerecon Output Contract

Use this skill before finalizing the prerecon answer.

You must return data that can be validated as `PreReconReport`.

Checklist:
- `framework_signals` contains only evidence-backed signals
- `candidate_routes` contains normalized route-like paths
- `warnings` contains ambiguities, missing evidence, or missing repository signals
- `remediation_hints` contains concrete next steps, not generic advice
- do not fabricate `repo_top_level_entries`; include only observed top-level names
- preserve scope/planner context but do not present it as discovered evidence
