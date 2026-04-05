Review 2 completed: 2026-04-04
Review 1 completed: 2026-04-04

# Plan: SMB authentication backend for spray engine

## Summary

Switch the spray engine's default authentication from LDAP to SMB via impacket's `SMBConnection.login()`. SMB is more reliable (port 445 is open on virtually every DC, unlike 389/636 which are commonly firewalled). Keep LDAP auth available behind a `--ldap-auth` flag for edge cases.

## Problem

The spray engine authenticates exclusively via LDAP (`check_auth` in `ldap/auth.py` using ldap3). When LDAP ports 389 and 636 are blocked, the spray cannot run at all — every attempt returns `ERROR_HOST_UNREACHABLE`. Meanwhile, SMB on port 445 is reachable (proven by `--null-session` working). Tools like CrackMapExec use SMB login for the same purpose.

## Goal

- `python3 spray.py spray -d dc01 -w CORP --users users.txt --passwords pwds.txt --lockout-window 5 --attempts 1` uses SMB auth by default on port 445.
- `--ldap-auth` flag on the `spray` subcommand switches back to LDAP-based authentication (with existing `--ssl`/`--port` behavior).
- All existing NT status codes are correctly mapped from impacket's `SessionError.getErrorCode()` to the `ERROR_*` constants the engine already uses.

## Design

### New module: `ad_spray/smb/auth.py`

SMB-based `check_auth`:

```python
def check_auth(
    dc_host: str,
    username: str,
    password: str,
    workgroup: str = "",
    port: int = 445,
) -> dict:
```

Implementation:
1. Strip domain prefixes from `username` before use: remove `DOMAIN\` prefix and `@domain` suffix (same logic as `ldap/auth.py:43-47`). This keeps the two backends consistent when user files contain qualified names like `CORP\jsmith`.
2. `SMBConnection(dc_host, dc_host, sess_port=port)` — opens TCP to port 445.
3. `smb.login(username, password, domain=workgroup)` — attempts NTLM auth.
4. On success: call `smb.logoff()` in a `try/finally` to release the TCP connection, then return `{"success": True, "status": "ERROR_SUCCESS", ...}`. Without explicit cleanup, thousands of leaked sockets accumulate over a spray.
5. On `SessionError`: extract `e.getErrorCode()`, map via `NT_STATUS_MAP` dict to our `ERROR_*` constants. The connection is implicitly closed on error, but wrap in `try/finally` for safety.
6. On socket/connection errors: return `ERROR_HOST_UNREACHABLE`.
7. On any other `Exception`: return `ERROR_GEN_FAILURE`. This mirrors the LDAP auth's three-tier pattern (`ldap/auth.py:66-92`) and prevents unexpected impacket exceptions (e.g., `NetBIOSError`) from crashing the spray mid-run.

NT status code mapping (hex → our constant):

| NT Status | Hex | Maps to |
|---|---|---|
| `STATUS_LOGON_FAILURE` | `0xC000006D` | `ERROR_LOGON_FAILURE` |
| `STATUS_ACCOUNT_DISABLED` | `0xC0000072` | `ERROR_ACCOUNT_DISABLED` |
| `STATUS_ACCOUNT_LOCKED_OUT` | `0xC0000234` | `ERROR_ACCOUNT_LOCKED_OUT` |
| `STATUS_PASSWORD_EXPIRED` | `0xC0000071` | `ERROR_PASSWORD_EXPIRED` |
| `STATUS_PASSWORD_MUST_CHANGE` | `0xC0000224` | `ERROR_PASSWORD_MUST_CHANGE` |
| `STATUS_ACCOUNT_EXPIRED` | `0xC0000193` | `ERROR_ACCOUNT_EXPIRED` |
| `STATUS_INVALID_LOGON_HOURS` | `0xC000006F` | `ERROR_INVALID_LOGON_HOURS` |
| `STATUS_INVALID_WORKSTATION` | `0xC0000070` | `ERROR_INVALID_WORKSTATION` |
| `STATUS_LOGON_TYPE_NOT_GRANTED` | `0xC000015B` | `ERROR_LOGON_TYPE_NOT_GRANTED` |
| `STATUS_NO_SUCH_USER` | `0xC0000064` | `ERROR_LOGON_FAILURE` |

Note: `STATUS_NO_SUCH_USER` maps to `ERROR_LOGON_FAILURE` (not `ERROR_NO_SUCH_USER`) because SMB returns this for valid-but-nonexistent accounts, and we don't want to skip users based on a potentially unreliable signal. **Known behavioral delta:** the LDAP path (`ldap/errors.py:10`) maps the equivalent AD sub-error `0x525` to `ERROR_NO_SUCH_USER`, which triggers user skipping in the engine (`engine.py:691-694`). This means `--ldap-auth` will skip nonexistent users while the default SMB path will keep retrying them. Operators should be aware of this difference.

### `ad_spray/smb/__init__.py`

New package init that exports `check_auth`.

### Engine update (`ad_spray/engine.py`)

The engine currently imports `check_auth` from `ad_spray.ldap` and calls it in `_check_credential` (line 294). Changes:

- Import both: `from .smb.auth import check_auth as smb_check_auth` and `from .ldap.auth import check_auth as ldap_check_auth`.
- In `_check_credential`: read `self.session.config.use_ldap_auth` to select backend. Do **not** add a separate `use_ldap_auth` parameter to `SprayEngine.__init__` — the config is the single source of truth and is already persisted, so `--resume` works correctly without any extra wiring.
- When using SMB auth, don't pass `use_ssl` (irrelevant for SMB). Default port to 445 when `config.port` is None.
- When using LDAP auth, pass all existing parameters unchanged.

### CLI update (`ad_spray/cli.py`)

- Add `--ldap-auth` flag to the `spray` subparser: `action="store_true"`, help text indicates it switches from the default SMB to LDAP authentication.
- Pass `use_ldap_auth=args.ldap_auth` through to `create_session` (which passes it to `SprayConfig`). The engine reads it from the config — no direct engine wiring needed.
- `--ssl` and `--port` on the `spray` subparser remain available — `--ssl` is only meaningful with `--ldap-auth`, and `--port` can override the SMB port too (default becomes 445 instead of 389). Emit a warning when `--ssl` is used without `--ldap-auth` (since SSL is meaningless for SMB auth).
- Add `'ldap_auth'` to the defaults loop (line 109-114) so `hasattr` is satisfied when the attr is missing.
- `get-policy` and `get-users` subcommands are unaffected — they use LDAP/RPC via their own code paths.

### Models update (`ad_spray/models.py`)

- Add `use_ldap_auth: bool = False` to `SprayConfig` dataclass so the auth method is persisted in the session and used correctly on `--resume`.
- **Important:** `SprayConfig.from_dict` uses `cls(**d)`. The default value `False` ensures old sessions saved without this field load correctly — `from_dict` receives a dict that lacks the key, and the dataclass default fills it in. No migration needed.

### Session creation (`ad_spray/session.py`)

- Add `use_ldap_auth: bool = False` parameter to `create_session()`.
- Pass it through to the `SprayConfig(...)` constructor (line 89-100).
- The config dict is persisted via `store.create(config=config.to_dict(), ...)` so the field is automatically saved.

### Config file (`ad_spray/config.py`)

- Add `ldap_auth` to the `[target]` section in `load_config()`: `result['ldap_auth'] = config.getboolean('target', 'ldap_auth', fallback=False)`.
- This ensures `--config` files can set `ldap_auth = true` under `[target]` and it flows through `merge_config_with_args` to `args.ldap_auth`.

### Existing LDAP auth

- `ad_spray/ldap/auth.py`: Unchanged. Still used when `--ldap-auth` is passed, and by `get-policy`/`get-users` for authenticated LDAP queries.

## Affected Components

- `ad_spray/smb/__init__.py`: New file. Package init exporting `check_auth`.
- `ad_spray/smb/auth.py`: New file. `check_auth()` using `SMBConnection.login()` with NT status code mapping. Must call `smb.logoff()` in `try/finally` on success to avoid socket leaks.
- `ad_spray/engine.py`: Import both auth backends. Read `self.session.config.use_ldap_auth` to select backend (not a constructor param). Default port 445 for SMB path.
- `ad_spray/cli.py`: Add `--ldap-auth` flag to `spray` subparser. Pass through to `create_session`. Warn when `--ssl` used without `--ldap-auth`. Add `'ldap_auth'` to defaults loop.
- `ad_spray/models.py`: Add `use_ldap_auth: bool = False` to `SprayConfig` (default ensures old session compat).
- `ad_spray/session.py`: Add `use_ldap_auth` param to `create_session()`, pass to `SprayConfig`.
- `ad_spray/config.py`: Add `ldap_auth` to `[target]` section in `load_config()`.

## Execution Notes

Executed: 2026-04-04

All plan items implemented with no deviations:

1. `ad_spray/smb/__init__.py`: Created package init exporting `check_auth`.
2. `ad_spray/smb/auth.py`: Created SMB `check_auth()` with NT status code mapping, domain prefix stripping, `smb.logoff()` in `try/finally`, and three-tier error handling (SessionError / socket.error / Exception).
3. `ad_spray/models.py`: Added `use_ldap_auth: bool = False` to `SprayConfig`. Old sessions deserialize correctly via default.
4. `ad_spray/session.py`: Added `use_ldap_auth` param to `create_session()`, passed through to `SprayConfig`.
5. `ad_spray/engine.py`: Replaced single `check_auth` import with dual `ldap_check_auth`/`smb_check_auth`. `_check_credential` reads `config.use_ldap_auth` to select backend.
6. `ad_spray/cli.py`: Added `--ldap-auth` flag, `ldap_auth` to defaults loop, `--ssl` warning without `--ldap-auth`, pass-through to `create_session`. Updated `--ssl` and `--port` help text.
7. `ad_spray/config.py`: Added `ldap_auth` to `[target]` section in `load_config()`.

Commit: a69781e
