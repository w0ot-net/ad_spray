# Plan: SMB authentication backend for spray engine

## Summary

Add an SMB-based authentication path using impacket's `SMBConnection.login()` as an alternative to the current LDAP bind. This allows spraying against DCs where ports 389/636 are firewalled but SMB/445 is accessible — a common scenario confirmed in the current engagement (ACCME DC blocks LDAP but allows SMB).

## Problem

The spray engine authenticates exclusively via LDAP (`check_auth` in `ldap/auth.py` using ldap3). When LDAP ports 389 and 636 are blocked, the spray cannot run at all — every attempt returns `ERROR_HOST_UNREACHABLE`. Meanwhile, SMB on port 445 is reachable (proven by `--null-session` working). Tools like CrackMapExec use SMB login for the same purpose.

## Goal

- `python3 spray.py spray -d dc01 -w CORP --users users.txt --passwords pwds.txt --lockout-window 5 --attempts 1` uses SMB auth by default on port 445.
- All existing NT status codes are correctly mapped from impacket's `SessionError.getErrorCode()` to the `ERROR_*` constants the engine already uses.
- LDAP auth is removed. SMB auth is the only authentication method — it's more reliable (works through more firewalls), faster (single TCP connection vs LDAP bind), and every DC exposes port 445.

## Design

### New function: `ad_spray/smb/auth.py`

Replace LDAP-based `check_auth` with SMB-based `check_auth`:

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

Note: `STATUS_NO_SUCH_USER` maps to `ERROR_LOGON_FAILURE` (not `ERROR_NO_SUCH_USER`) because SMB returns this for valid-but-nonexistent accounts, and we don't want to skip users based on a potentially unreliable signal. If a DC is configured to hide user existence, this code won't appear anyway.

### Engine update (`ad_spray/engine.py`)

Change the import from `from .ldap import check_auth` to `from .smb import check_auth`.

Remove `use_ssl` and `port` parameters from `_check_credential` — SMB always uses port 445 (or whatever was configured). The `config.port` field can be passed through but defaults to 445.

### CLI update (`ad_spray/cli.py`)

- Remove `--ssl` from the `spray` subparser — it was only relevant for LDAP.
- Default `--port` to 445 instead of relying on the LDAP 389/636 logic.
- The `get-policy` and `get-users` subcommands keep `--ssl` since they still use LDAP for authenticated queries.

### Remove LDAP auth dependency from engine

- `ad_spray/ldap/auth.py`: Keep the file (it's still used by `get-policy`/`get-users` for LDAP binds via `ADConnection`). But the spray engine no longer imports from it.
- `ad_spray/engine.py`: Import `check_auth` from `ad_spray.smb` instead of `ad_spray.ldap`.

### `ad_spray/smb/__init__.py`

New package init that exports `check_auth`.

## Affected Components

- `ad_spray/smb/__init__.py`: New file. Package init exporting `check_auth`.
- `ad_spray/smb/auth.py`: New file. `check_auth()` using `SMBConnection.login()` with NT status code mapping.
- `ad_spray/engine.py`: Change import of `check_auth` from `ldap` to `smb`. Remove `use_ssl` from `_check_credential` call (line 298).
- `ad_spray/cli.py`: Remove `--ssl` from `spray` subparser. Keep it on `get-policy`/`get-users`.
