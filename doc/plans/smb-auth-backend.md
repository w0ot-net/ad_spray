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
1. `SMBConnection(dc_host, dc_host, sess_port=port)` — opens TCP to port 445.
2. `smb.login(username, password, domain=workgroup)` — attempts NTLM auth.
3. On success: return `{"success": True, "status": "ERROR_SUCCESS", ...}`.
4. On `SessionError`: extract `e.getErrorCode()`, map via `NT_STATUS_MAP` dict to our `ERROR_*` constants.
5. On socket/connection errors: return `ERROR_HOST_UNREACHABLE`.

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

Note: `STATUS_NO_SUCH_USER` maps to `ERROR_LOGON_FAILURE` (not `ERROR_NO_SUCH_USER`) because SMB returns this for valid-but-nonexistent accounts, and we don't want to skip users based on a potentially unreliable signal.

### `ad_spray/smb/__init__.py`

New package init that exports `check_auth`.

### Engine update (`ad_spray/engine.py`)

The engine currently imports `check_auth` from `ad_spray.ldap` and calls it in `_check_credential` (line 294). Changes:

- Import both: `from .smb.auth import check_auth as smb_check_auth` and `from .ldap.auth import check_auth as ldap_check_auth`.
- Add `use_ldap_auth: bool = False` parameter to `SprayEngine.__init__`.
- In `_check_credential`: call `smb_check_auth` by default, or `ldap_check_auth` when `use_ldap_auth` is True.
- When using SMB auth, don't pass `use_ssl` (irrelevant for SMB). Default port to 445 when `config.port` is None.
- When using LDAP auth, pass all existing parameters unchanged.

### CLI update (`ad_spray/cli.py`)

- Add `--ldap-auth` flag to the `spray` subparser: `action="store_true"`, help text indicates it switches from the default SMB to LDAP authentication.
- Pass `use_ldap_auth=args.ldap_auth` through to `SprayEngine`.
- `--ssl` and `--port` on the `spray` subparser remain available — `--ssl` is only meaningful with `--ldap-auth`, and `--port` can override the SMB port too (default becomes 445 instead of 389).
- `get-policy` and `get-users` subcommands are unaffected — they use LDAP/RPC via their own code paths.

### Models update (`ad_spray/models.py`)

- Add `use_ldap_auth: bool = False` to `SprayConfig` dataclass so the auth method is persisted in the session and used correctly on `--resume`.

### Existing LDAP auth

- `ad_spray/ldap/auth.py`: Unchanged. Still used when `--ldap-auth` is passed, and by `get-policy`/`get-users` for authenticated LDAP queries.

## Affected Components

- `ad_spray/smb/__init__.py`: New file. Package init exporting `check_auth`.
- `ad_spray/smb/auth.py`: New file. `check_auth()` using `SMBConnection.login()` with NT status code mapping.
- `ad_spray/engine.py`: Import both auth backends. Select based on `use_ldap_auth` flag. Default port 445 for SMB path.
- `ad_spray/cli.py`: Add `--ldap-auth` flag to `spray` subparser. Pass through to engine.
- `ad_spray/models.py`: Add `use_ldap_auth` field to `SprayConfig`.
