"""Tests for recon markdown report generation."""

from __future__ import annotations

from adversa.recon.reports import generate_recon_markdown
from adversa.state.models import (
    AuthorizationGuard,
    AuthzCandidate,
    InputVector,
    NetworkEntity,
    NetworkFlow,
    PrivilegeRole,
    ReconEndpoint,
    ReconReport,
)


def _minimal_report(**kwargs) -> ReconReport:
    defaults = dict(
        target_url="https://example.com",
        canonical_url="https://example.com",
        host="example.com",
        path="/",
    )
    defaults.update(kwargs)
    return ReconReport(**defaults)


def test_generate_recon_markdown_minimal() -> None:
    """Test markdown generation with empty report."""
    report = _minimal_report()
    markdown = generate_recon_markdown(report)

    assert "# Recon Analysis Report" in markdown
    assert "**Target:** https://example.com" in markdown
    assert "## 1. Executive Summary" in markdown
    assert "## 4. API Endpoint Inventory" in markdown
    assert "_No endpoints mapped._" in markdown


def test_generate_recon_markdown_executive_summary() -> None:
    """Test executive summary section with stats."""
    report = _minimal_report(
        executive_summary="A Node.js REST API with JWT auth and PostgreSQL backend.",
        endpoints=[
            ReconEndpoint(
                method="GET",
                path="/api/users",
                required_role="admin",
                auth_mechanism="Bearer Token + requireAdmin()",
                handler_location="controllers/users.js:10",
                description="List all users",
                evidence_level="high",
            )
        ],
        authz_candidates=[
            AuthzCandidate(
                candidate_type="horizontal",
                priority="high",
                endpoint_pattern="/api/users/{id}",
                object_id_param="id",
                data_type="user_data",
                notes="No ownership check at handler.",
            )
        ],
    )
    markdown = generate_recon_markdown(report)

    assert "A Node.js REST API with JWT auth" in markdown
    assert "| Endpoints Mapped | 1 |" in markdown
    assert "| High-Priority Authz Candidates | 1 |" in markdown


def test_generate_recon_markdown_technology_map() -> None:
    """Test technology map section."""
    report = _minimal_report(
        frontend_tech=["React 18", "TypeScript"],
        backend_tech=["Node.js 20", "Express 4"],
        infrastructure=["AWS ECS", "CloudFront"],
    )
    markdown = generate_recon_markdown(report)

    assert "## 2. Technology & Service Map" in markdown
    assert "| Frontend | React 18, TypeScript |" in markdown
    assert "| Backend | Node.js 20, Express 4 |" in markdown
    assert "| Infrastructure | AWS ECS, CloudFront |" in markdown


def test_generate_recon_markdown_auth_section() -> None:
    """Test auth and session management section."""
    report = _minimal_report(
        privilege_roles=[
            PrivilegeRole(name="anon", privilege_level=0, scope="Global", middleware_location=""),
            PrivilegeRole(
                name="user",
                privilege_level=5,
                scope="Global",
                middleware_location="middleware/auth.js:12",
                default_landing="/dashboard",
            ),
            PrivilegeRole(
                name="admin",
                privilege_level=10,
                scope="Global",
                middleware_location="middleware/auth.js:30",
                default_landing="/admin",
            ),
        ],
        authorization_guards=[
            AuthorizationGuard(
                name="requireAuth",
                category="Auth",
                statement="Validates JWT and sets req.user before handler executes.",
            ),
            AuthorizationGuard(
                name="checkOwnership",
                category="ObjectOwnership",
                statement="Verifies req.user.id matches resource owner_id.",
            ),
        ],
    )
    markdown = generate_recon_markdown(report)

    assert "## 3. Authentication & Session Management" in markdown
    assert "### Privilege Roles" in markdown
    assert "| anon | 0 |" in markdown
    assert "| admin | 10 |" in markdown
    assert "`middleware/auth.js:12`" in markdown
    assert "### Authorization Guards" in markdown
    assert "| `requireAuth` |" in markdown
    assert "| `checkOwnership` |" in markdown


def test_generate_recon_markdown_endpoint_inventory() -> None:
    """Test API endpoint inventory section."""
    report = _minimal_report(
        endpoints=[
            ReconEndpoint(
                method="GET",
                path="/api/orders/{order_id}",
                required_role="user",
                object_id_params=["order_id"],
                auth_mechanism="Bearer Token + requireAuth()",
                handler_location="controllers/orders.py:42",
                description="Get order by ID",
                evidence_level="high",
            ),
            ReconEndpoint(
                method="DELETE",
                path="/api/admin/users/{user_id}",
                required_role="admin",
                object_id_params=["user_id"],
                auth_mechanism="Bearer Token + requireAdmin()",
                handler_location="controllers/admin.py:88",
                description="Delete user (admin only)",
                evidence_level="high",
            ),
        ],
    )
    markdown = generate_recon_markdown(report)

    assert "## 4. API Endpoint Inventory" in markdown
    assert "| GET | `/api/orders/{order_id}` |" in markdown
    assert "| DELETE | `/api/admin/users/{user_id}` |" in markdown
    assert "`order_id`" in markdown
    assert "`controllers/orders.py:42`" in markdown


def test_generate_recon_markdown_input_vectors() -> None:
    """Test input vectors section highlights risky unvalidated inputs."""
    report = _minimal_report(
        input_vectors=[
            InputVector(
                vector_type="url_param",
                name="order_id",
                endpoint="GET /api/orders/{order_id}",
                location="controllers/orders.py:43",
                validation_present=False,
                flows_to_sink=True,
                evidence_level="high",
            ),
            InputVector(
                vector_type="post_body",
                name="email",
                endpoint="POST /api/users",
                location="controllers/users.py:20",
                validation_present=True,
                flows_to_sink=False,
                evidence_level="high",
            ),
        ],
    )
    markdown = generate_recon_markdown(report)

    assert "## 5. Input Vectors" in markdown
    assert "### Unvalidated Inputs Reaching Sinks" in markdown
    assert "| url_param | `order_id` |" in markdown
    # Validated input should not appear in the risky section
    assert "### All Input Vectors" in markdown
    assert "| post_body | `email` |" in markdown
    assert "**No**" in markdown  # validation_present=False is bolded


def test_generate_recon_markdown_network_map() -> None:
    """Test network & interaction map section."""
    report = _minimal_report(
        network_entities=[
            NetworkEntity(
                title="API Server",
                entity_type="Service",
                zone="App",
                tech="Node/Express",
                data_sensitivity=["PII", "Tokens"],
            ),
            NetworkEntity(
                title="PostgreSQL",
                entity_type="DataStore",
                zone="Data",
                tech="PostgreSQL 15",
                data_sensitivity=["PII", "Payments"],
            ),
        ],
        network_flows=[
            NetworkFlow(
                from_entity="API Server",
                to_entity="PostgreSQL",
                channel="TCP",
                path_port=":5432",
                guards=["vpc-only"],
                touches=["PII", "Payments"],
            ),
        ],
    )
    markdown = generate_recon_markdown(report)

    assert "## 6. Network & Interaction Map" in markdown
    assert "### Entities" in markdown
    assert "| **API Server** |" in markdown
    assert "| **PostgreSQL** |" in markdown
    assert "### Flows" in markdown
    assert "| API Server | PostgreSQL | TCP | `:5432` |" in markdown
    assert "vpc-only" in markdown


def test_generate_recon_markdown_privilege_lattice() -> None:
    """Test privilege lattice ASCII art in section 7."""
    report = _minimal_report(
        privilege_roles=[
            PrivilegeRole(name="anon", privilege_level=0, scope="Global"),
            PrivilegeRole(name="user", privilege_level=5, scope="Global", default_landing="/dashboard"),
            PrivilegeRole(name="admin", privilege_level=10, scope="Global", default_landing="/admin"),
        ],
    )
    markdown = generate_recon_markdown(report)

    assert "## 7. Role & Privilege Architecture" in markdown
    assert "### Privilege Lattice" in markdown
    assert "[10] admin" in markdown
    assert "[ 5] user" in markdown
    assert "[ 0] anon" in markdown
    assert "### Role Entry Points" in markdown
    assert "**admin**: lands at `/admin`" in markdown


def test_generate_recon_markdown_authz_candidates() -> None:
    """Test authorization vulnerability candidates section."""
    report = _minimal_report(
        authz_candidates=[
            AuthzCandidate(
                candidate_type="horizontal",
                priority="high",
                endpoint_pattern="/api/orders/{order_id}",
                object_id_param="order_id",
                data_type="financial",
                notes="Handler fetches order by ID without verifying req.user.id == order.user_id.",
            ),
            AuthzCandidate(
                candidate_type="vertical",
                priority="high",
                endpoint_pattern="/api/admin/users",
                object_id_param=None,
                data_type="admin_config",
                notes="Route is in /admin prefix but only checks isAuthenticated, not isAdmin.",
            ),
            AuthzCandidate(
                candidate_type="context_based",
                priority="medium",
                endpoint_pattern="/api/checkout/confirm",
                object_id_param=None,
                data_type="financial",
                notes="Checkout step does not re-validate cart state from previous step.",
            ),
        ],
    )
    markdown = generate_recon_markdown(report)

    assert "## 8. Authorization Vulnerability Candidates" in markdown
    assert "### Horizontal (IDOR" in markdown
    assert "### Vertical (Privilege Escalation)" in markdown
    assert "### Context-Based (Workflow Bypass)" in markdown
    assert "**HIGH**" in markdown
    assert "`/api/orders/{order_id}`" in markdown
    assert "`order_id`" in markdown


def test_generate_recon_markdown_live_observations() -> None:
    """Test live browser observations section."""
    report = _minimal_report(
        live_observations=[
            "GET https://example.com → 200 OK (React SPA, no auth prompt)",
            "GET /api/users → 401 Unauthorized (Bearer token required)",
            "POST /api/auth/login → 200 OK, sets httpOnly JWT cookie",
        ],
    )
    markdown = generate_recon_markdown(report)

    assert "## 9. Live Browser Observations" in markdown
    assert "GET https://example.com → 200 OK" in markdown
    assert "401 Unauthorized" in markdown
    assert "httpOnly JWT cookie" in markdown


def test_generate_recon_markdown_no_live_section_when_empty() -> None:
    """Test that live observations section is omitted when empty."""
    report = _minimal_report()
    markdown = generate_recon_markdown(report)
    assert "## 9. Live Browser Observations" not in markdown


def test_generate_recon_markdown_warnings() -> None:
    """Test warnings and remediation hints section."""
    report = _minimal_report(
        warnings=["Could not determine ownership check for /api/orders/{id}"],
        remediation_hints=["Check orderController.getById for missing user ID assertion"],
    )
    markdown = generate_recon_markdown(report)

    assert "## Warnings & Remediation Hints" in markdown
    assert "⚠️ Could not determine ownership check" in markdown
    assert "💡 Check orderController.getById" in markdown
