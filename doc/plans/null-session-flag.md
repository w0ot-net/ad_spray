# Plan: `--null-session` flag with RPC/SMB policy fetch

## Summary

Add a `--null-session` flag to `get-policy` and `get-users` commands that performs anonymous authentication without requiring `-w`, `-u`, or `-p` flags. When `--null-session` is used, both commands switch from LDAP to RPC via impacket's SAMR interface, since DCs commonly block anonymous LDAP reads but allow null SMB/RPC sessions.

## Problem

To perform a null/anonymous session, the user currently must pass `-w example.com -u '' -p ''`, which is awkward. Additionally, even with the recent anonymous LDAP bind fix, both `get-policy` and `get-users` fail on DCs that block anonymous LDAP reads — despite those same DCs allowing null SMB/RPC sessions (as confirmed by enum4linux retrieving the policy and full user list via `rpcclient`/SAMR).

## Goal

- `python3 spray.py get-policy -d dc01.example.com --null-session` fetches the domain policy via RPC without requiring `-w`, `-u`, or `-p`.
- `python3 spray.py get-users -d dc01.example.com --null-session` enumerates users via RPC/SAMR without requiring `-w`, `-u`, or `-p`.
- Authenticated flows are unchanged.

## Design

### CLI changes (`ad_spray/cli.py`)

Add `--null-session` flag to both `get-policy` and `get-users` parsers. When set:
- Skip validation for `-w`, `-u`, `-p` (they become optional).
- For `get-policy`: call `fetch_policy_rpc()` instead of the LDAP-based `fetch_policy()`.
- For `get-users`: call `fetch_users_rpc()` instead of the LDAP-based `fetch_users()`.

### New module: `ad_spray/rpc/samr.py`

Create a thin RPC module using impacket's SAMR interface for null session operations. Two public functions:

```python
def fetch_policy_rpc(dc_host: str, port: int = 445) -> DomainPolicy:
def fetch_users_rpc(dc_host: str, port: int = 445) -> List[str]:
```

Both functions share the same connection setup:
1. Connect to the DC over SMB with anonymous credentials (`smbconnection.SMBConnection` with empty user/password).
2. Open the SAMR named pipe, bind to the SAMR interface.
3. `SamrConnect` → `SamrEnumerateDomainsInSamServer` → `SamrLookupDomainInSamServer` (skip `Builtin`) → `SamrOpenDomain`.

**Policy fetch** (`fetch_policy_rpc`):
- `SamrQueryInformationDomain` with info level 1 (`DomainPasswordInformation`): `MinPasswordLength`, `PasswordHistoryLength`, `PasswordProperties` (complexity bitmask).
- `SamrQueryInformationDomain` with info level 12 (`DomainLockoutInformation`): `LockoutThreshold`, `LockoutDuration`, `LockoutObservationWindow`.
- Duration values from SAMR are in FILETIME format (100-nanosecond intervals, stored as negative `LARGE_INTEGER`). Reuse `to_minutes()` from shared location.

**User enumeration** (`fetch_users_rpc`):
- `SamrEnumerateUsersInDomain` with `UserAccountControl` mask `0x10` (normal user accounts).
- Returns sorted list of sAMAccountName strings.

Key SAMR fields mapping for policy:
- `DomainPasswordInformation` (level 1): `MinPasswordLength`, `PasswordHistoryLength`, `PasswordProperties`
- `DomainLockoutInformation` (level 12): `LockoutThreshold`, `LockoutDuration`, `LockoutObservationWindow`

### Shared utility extraction

Move `to_minutes()` from `ad_spray/ldap/connection.py` to `ad_spray/constants.py` (already exists) so both LDAP and RPC code can use it without circular imports. Update the import in `connection.py`.

### Previous anonymous bind workaround

Keep the `_auth_params()` anonymous bind logic and the `is None` checks in `cli.py` from the previous commits. They're harmless and still useful if someone explicitly passes empty creds without `--null-session`.

## Affected Components

- `ad_spray/cli.py`: Add `--null-session` flag to `get-policy` and `get-users` parsers. Update validation logic to skip `-w/-u/-p` checks when `--null-session` is set. Route both commands to RPC functions when flag is set.
- `ad_spray/rpc/__init__.py`: New file. Empty init for rpc package.
- `ad_spray/rpc/samr.py`: New file. `fetch_policy_rpc(dc_host, port)` and `fetch_users_rpc(dc_host, port)` using impacket SAMR via null SMB session.
- `ad_spray/constants.py`: Add `to_minutes()` utility moved from `ldap/connection.py`.
- `ad_spray/ldap/connection.py`: Update import of `to_minutes` to use `ad_spray.constants` instead of local definition.
