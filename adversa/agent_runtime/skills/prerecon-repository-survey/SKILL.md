# Prerecon Repository Survey

Use this skill when you need to understand how the authorized application is structured before recon.

Goals:
- identify framework/runtime signals
- find entry points and route declarations
- find auth-related components, middleware, guards, or configuration
- capture only evidence-backed findings

Method:
1. Start with `ls` and `glob` under the authorized repo path.
2. Use `grep` to find likely route declarations, auth markers, middleware, guards, and config files.
3. Read only the most relevant files needed to support conclusions.
4. Prefer a few strong signals over a noisy file dump.

Output expectations:
- framework/runtime signals with concrete file support
- candidate routes or surfaces
- warnings when route discovery is weak or ambiguous
- remediation hints when the repo does not expose enough signals
