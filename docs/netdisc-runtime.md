# Network Discovery Runtime

This document describes how Adversa's Network Discovery phase currently executes, what tools it uses, what inputs it consumes, and which artifacts it writes.

## Overview

Network Discovery (netdisc) sits between Pre-Recon and Recon in the workflow:

```
intake → prerecon → netdisc → recon → vuln → report
```

Its job is to enumerate the live network surface of the authorized target and produce a `NetworkDiscoveryReport` that Recon can correlate with the static code intelligence from Pre-Recon. The current implementation is **fully deterministic** — it uses no LLM or agent at this phase. All discovery is performed by purpose-built tool wrappers.

The important design rule is:

- netdisc only operates on hosts that are in scope per the `scope.json` from Intake
- active scanning (port discovery) is explicitly opt-in and disabled by default
- if network discovery is disabled, a stub artifact is produced so downstream phases can still run

## Execution Flow

The current flow is:

1. Temporal workflow enters the `netdisc` phase.
2. `run_phase_activity(...)` in `adversa/workflow_temporal/activities.py` dispatches netdisc handling.
3. `_write_netdisc_artifacts(...)` calls `build_network_discovery_report(...)` in `adversa/netdisc/controller.py`.
4. `build_network_discovery_report(...)`:
   - loads and validates the `ScopeContract` from `intake/scope.json`
   - reads `network_discovery_enabled` and `active_scanning_enabled` from config
   - if passive discovery is enabled: runs subfinder → HTTP fingerprinting → TLS inspection, all restricted to in-scope hosts
   - if active scanning is enabled: runs nmap port scan on in-scope hosts only
   - deduplicates and sorts all results deterministically
   - returns a `NetworkDiscoveryReport`
5. The activity generates `network_discovery.md` from the report.
6. The phase output is indexed into the run artifact store.

## Inputs

Network Discovery depends on:

- target URL
- workspace root / run directory
- effective config path
- Intake artifacts:
  - `intake/scope.json` — used for host scope classification and exclusion enforcement

`_load_scope_contract(...)` in `adversa/netdisc/controller.py` loads the scope contract. If it is missing, netdisc continues but emits a warning and skips scope classification.

Discovery scope is enforced by `_is_host_in_scope(...)`:

- any host matching a scope exclusion is rejected
- hosts matching `allowed_hosts`, `allowed_subdomains`, or `normalized_host` are accepted as in-scope
- all other hosts are classified as `out_of_scope` and skipped for fingerprinting and scanning

## Tools

Network Discovery uses four deterministic tool wrappers from `adversa/netdisc/tools.py`. No LLM is involved.

### 1. SubfinderWrapper

Purpose:

- passive subdomain enumeration using `subfinder`
- discovers hostnames associated with the target domain without active probing

Config:

- timeout: 30 seconds
- max targets: 50

All discovered hosts are classified as `in_scope` or `out_of_scope` against the `ScopeContract` before any further processing.

Activation:

- runs when `network_discovery_enabled = true` in `adversa.toml`

### 2. HttpFingerprinter

Purpose:

- HTTP service fingerprinting for in-scope hosts
- collects HTTP status codes, server headers, detected technologies, TLS state, and redirect chains

Config:

- timeout: 15 seconds per host

Activation:

- runs for each in-scope host discovered by subfinder, when passive discovery is enabled

### 3. TLSInspector

Purpose:

- TLS/SSL certificate inspection for in-scope HTTPS hosts
- collects TLS version, cipher suite, certificate expiry, self-signed status, and SAN entries

Config:

- timeout: 10 seconds per host

Activation:

- runs for each in-scope host when passive discovery is enabled

### 4. NmapWrapper

Purpose:

- active port scanning for in-scope hosts
- discovers open ports, protocol, service name, version, and banner

Config:

- timeout: 60 seconds per host

Activation:

- **disabled by default**
- only runs when `active_scanning_enabled = true` is explicitly set in `adversa.toml`
- restricted to in-scope hosts only

## No Middleware

Because netdisc uses no LLM or agent, it does not use the rules middleware or runtime boundary middleware layers. Scope enforcement is handled directly and deterministically by the controller using the `ScopeContract`.

## Expected Structured Output

The netdisc controller returns a `NetworkDiscoveryReport`.

Current model location:

- `adversa/state/models.py`

The report currently includes:

- target and canonical URL information
- normalized host and path
- `passive_discovery_enabled` and `active_scanning_enabled` flags
- typed discovered hosts with scope classification
- typed service fingerprints with technology detection and redirect chains
- typed TLS observations with certificate metadata
- typed port/service records
- preserved `scope_inputs`
- warnings and remediation hints

Important nested structures include:

- `DiscoveredHost`
- `ServiceFingerprint`
- `TLSObservation`
- `PortService`

Each includes an `evidence_level` field (`high`, `medium`, `low`).

After the controller returns its result, all lists are deduplicated and sorted deterministically before being written to disk.

## Artifacts Written

Network Discovery writes into the run workspace under:

- `runs/<workspace>/<run_id>/netdisc/`

Current phase artifacts include:

- `network_discovery.md`
- `network_discovery.json`
- `output.json`
- `summary.md`
- `coverage.json`
- `evidence/baseline.json`

### `network_discovery.md`

The **primary deliverable** — a pentester-friendly markdown report generated deterministically from the `NetworkDiscoveryReport`. No tokens are spent on this; it is generated programmatically by `generate_netdisc_markdown(...)` in `adversa/netdisc/reports.py`.

The report contains five sections:

1. Executive Summary — host counts, scope split, tool coverage table; stub notice if passive discovery was disabled
2. Discovered Hosts — in-scope and out-of-scope host tables with IP resolution and discovery source
3. HTTP Service Fingerprints — status, server header, technology stack, TLS flag, redirect chains
4. TLS/SSL Certificate Analysis — version, cipher, expiry, self-signed/expired flags, SAN entries
5. Port & Service Discovery — open ports table; absent if active scanning was not enabled

This file is the primary input consumed by the Recon phase.

### `network_discovery.json`

Minimal workflow metadata artifact.

Contents:

- the normalized `NetworkDiscoveryReport`

### `output.json`

The phase-level shared output contract.

Contents include:

- phase metadata
- summary
- evidence references
- a netdisc data section with discovery counts and flags
- agent runtime metadata

### `summary.md`

A human-readable phase summary written as part of the shared phase artifact contract.

### `coverage.json`

Coverage and execution accounting for the netdisc phase.

Current contents include counts for:

- discovered hosts
- service fingerprints
- TLS observations
- port services

### `evidence/baseline.json`

A compact evidence pack for netdisc.

Current contents include:

- target URL and canonical URL
- all discovered hosts with scope classification
- all service fingerprints
- all TLS observations
- all port services
- `scope_inputs`

## Schema and Validation

Network Discovery output is validated through:

1. Pydantic validation against `NetworkDiscoveryReport`
2. deterministic deduplication and sorting in the controller
3. shared phase artifact writing and indexing
4. schema export coverage in `adversa/state/schemas.py`
5. pytest coverage in `tests/test_netdisc.py`, `tests/test_netdisc_markdown.py`, `tests/test_phase_outputs.py`, and `tests/test_phase_schemas.py`

## Failure Handling

Provider and runtime failures are handled at the activity boundary in `adversa/workflow_temporal/activities.py`.

Current behavior:

- if `scope.json` is missing, a warning is emitted and discovery continues without scope classification
- if a tool (subfinder, httpx, openssl, nmap) is unavailable or times out, that section is skipped gracefully and warnings are added to the report
- activity failures are raised as typed Temporal `ApplicationError`s
- transient failures remain retryable under the Temporal retry policy

## Configuration

Key settings in `adversa.toml` under `[safety]`:

| Key | Default | Effect |
|-----|---------|--------|
| `network_discovery_enabled` | `false` | Enables passive discovery (subfinder, HTTP fingerprinting, TLS inspection) |
| `active_scanning_enabled` | `false` | Enables active port scanning via nmap (requires explicit opt-in) |

If both are `false`, netdisc emits a stub artifact and the workflow continues.

## Where To Look In Code

Primary files:

- `adversa/netdisc/controller.py`
- `adversa/netdisc/tools.py`
- `adversa/netdisc/reports.py`
- `adversa/workflow_temporal/activities.py`
- `adversa/state/models.py`
- `tests/test_netdisc.py`
- `tests/test_netdisc_markdown.py`

## Current Boundaries

What netdisc does now:

- passively enumerates subdomains and fingerprints in-scope services
- classifies all discovered hosts against the authorized scope
- optionally scans open ports (explicit opt-in only)
- writes a deterministic, schema-valid network discovery report
- generates a markdown surface map for Recon to consume

What netdisc does not do:

- use an LLM or agent for any decision
- probe or interact with services beyond passive fingerprinting (unless active scanning is enabled)
- operate outside the authorized scope
- perform vulnerability testing or exploit generation

Recon should consume `network_discovery.md` as an upstream artifact rather than re-running network discovery from scratch.
