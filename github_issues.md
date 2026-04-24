# GitHub Issues — Apache Superset Vulnerability Remediation

---

## Issue 1: SQL Injection via Unsanitized Guest Token RLS Clauses

**Title:** `[Security] SQL Injection via unsanitized Row-Level Security clauses in guest tokens`

**Labels:** `security`, `critical`, `embedded`

### Summary

Guest token RLS (Row-Level Security) clauses are injected directly into SQL queries as raw text without any validation or sanitization, enabling SQL injection attacks.

### Affected Code

`superset/connectors/sqla/models.py`, lines 772-778:

```python
for rule in security_manager.get_guest_rls_filters(self):
    clause = self.text(
        f"({template_processor.process_template(rule['clause'])})"
    )
    all_filters.append(clause)
```

The `clause` value from the guest token is passed through Jinja template processing and then directly into `sqlalchemy.text()`, which treats it as raw SQL. There is no sanitization, parameterization, or structural validation.

The TODO comment at `superset/security/api.py:188` acknowledges this gap:
```python
# check rls rules for validity?
```

### Attack Scenario

1. An admin (or attacker with a forged guest token) creates a guest token with a malicious RLS rule:
   ```json
   {
     "rls_rules": [{"clause": "1=1 UNION SELECT username, password, email FROM ab_user--"}]
   }
   ```
2. The clause is injected verbatim into the WHERE clause of any query run against the embedded dashboard's datasets.
3. The attacker exfiltrates data from any table accessible to the database connection.

### Impact

- **Severity:** Critical
- Full data exfiltration from connected databases
- Bypass of all row-level security policies
- When combined with the default guest token JWT secret, this is exploitable by unauthenticated attackers

### Proposed Fix

Validate RLS clauses at guest token creation time using `sanitize_clause()` from `superset/sql/parse.py`. Reject clauses that contain multiple statements, UNION, subqueries, or DDL/DML keywords. Apply the same validation at query execution time as a defense-in-depth measure.

---

## Issue 2: Default Guest Token JWT Secret Has No Startup Validation

**Title:** `[Security] Default guest token JWT secret allows token forgery — no startup validation`

**Labels:** `security`, `critical`, `embedded`, `configuration`

### Summary

The `GUEST_TOKEN_JWT_SECRET` configuration defaults to a hardcoded string (`"test-guest-secret-change-me"`) and, unlike `SECRET_KEY`, has **no runtime check** that blocks startup if the default is unchanged. Any deployment that enables embedded dashboards without changing this value is vulnerable to guest token forgery.

### Affected Code

**Default value** — `superset/config.py:2346`:
```python
GUEST_TOKEN_JWT_SECRET = "test-guest-secret-change-me"
```

**SECRET_KEY has a startup check** — `superset/initialization/__init__.py:644-655`:
```python
if self.config["SECRET_KEY"] == CHANGE_ME_SECRET_KEY:
    ...
    logger.error("Refusing to start due to insecure SECRET_KEY")
    sys.exit(1)
```

**GUEST_TOKEN_JWT_SECRET has no equivalent check.** The token is signed with HS256 using this secret (`superset/security/manager.py:3149`), so anyone who knows the default can forge valid tokens.

### Attack Scenario

1. Attacker knows the default secret (it's in the public source code).
2. Attacker crafts a JWT with arbitrary `user`, `resources`, and `rls_rules` claims.
3. Attacker sends requests to embedded dashboard endpoints with the forged token in the `X-GuestToken` header.
4. Superset accepts the token and grants access to the specified dashboards with the specified RLS rules.

### Impact

- **Severity:** Critical
- Authentication bypass for all embedded dashboards
- Combined with the RLS SQL injection issue, enables unauthenticated data exfiltration
- Affects any deployment where `EMBEDDED_SUPERSET` is enabled and the default secret was not changed

### Proposed Fix

Add a startup check in `SupersetAppInitializer.check_secret_key()` (or a new method) that refuses to start when `EMBEDDED_SUPERSET` is enabled and `GUEST_TOKEN_JWT_SECRET` is still set to the default value. Mirror the existing `SECRET_KEY` validation pattern.

---

## Issue 3: SSRF via Database Connection Validation Endpoint

**Title:** `[Security] SSRF — database validation endpoint allows probing internal networks`

**Labels:** `security`, `high`, `ssrf`, `database`

### Summary

The `/api/v1/database/validate_parameters/` endpoint accepts user-supplied `host` and `port` values and performs DNS resolution (`socket.getaddrinfo`) and TCP connection attempts (`socket.connect`) against them with no restriction on internal or private IP ranges. The same lack of validation exists in the database creation/connection flow.

### Affected Code

**Validation endpoint** — `superset/databases/api.py:1952`:
Calls `engine_spec.validate_parameters()` which calls:

**DNS resolution** — `superset/utils/network.py:45`:
```python
def is_hostname_valid(host: str) -> bool:
    socket.getaddrinfo(host, None)
```

**TCP port probe** — `superset/utils/network.py:25`:
```python
def is_port_open(host: str, port: int) -> bool:
    s.connect(sockaddr)
```

**No hostname/IP validation** — `superset/db_engine_specs/base.py:2719-2755`:
The `validate_parameters` method passes user input directly to these functions without checking if the resolved IP is private, loopback, or link-local.

**Database URI validation** — `superset/security/analytics_db_safety.py`:
Only blocks specific *dialects* (sqlite, shillelagh). Does not validate hostnames or IPs.

### Attack Scenario

1. Authenticated user with database creation permission sends:
   ```json
   POST /api/v1/database/validate_parameters/
   {"engine": "postgresql", "parameters": {"host": "169.254.169.254", "port": 80}}
   ```
2. Superset's server makes a TCP connection to the cloud metadata endpoint.
3. Attacker uses response timing and error messages to map internal services.
4. Through actual database connections (not just validation), attacker can exfiltrate data from internal databases or cloud metadata services.

### Impact

- **Severity:** High
- Internal network port scanning and service discovery
- Cloud metadata endpoint access (AWS IMDS, GCP metadata, Azure IMDS) — potential credential theft
- Probing of internal databases, caches (Redis, Memcached), and other services

### Proposed Fix

Add an IP validation layer that:
1. Resolves the hostname to IP addresses
2. Rejects private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8), link-local (169.254.0.0/16), and other non-routable addresses
3. Apply this check in both `validate_parameters` and the database creation/connection flow
4. Make the blocklist configurable via a new `BLOCKED_DB_HOST_RANGES` config option for environments that legitimately need internal database access
