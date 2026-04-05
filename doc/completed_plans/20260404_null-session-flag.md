Review 1 completed: 2026-04-04

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
- Early-return branch at the top of `cmd_get_policy` / `cmd_get_users`: validate only `-d`, then call the RPC function and return. This avoids wrapping each `-w/-u/-p` check in conditionals.
- Pass `args.port` to `fetch_policy_rpc()` / `fetch_users_rpc()` when provided, falling back to the default 445.
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
- Duration values from SAMR are returned as impacket `LARGE_INTEGER` structs (with `HighPart` and `LowPart` fields), not plain Python ints. Extract the raw int via `(high << 32) | low` before passing to `to_minutes()`. Write a local helper `_large_int_to_minutes(li)` in `samr.py` that performs this extraction and delegates to `to_minutes()`.

**User enumeration** (`fetch_users_rpc`):
- `SamrEnumerateUsersInDomain` with `UserAccountControl` mask `0x10` (`UF_NORMAL_ACCOUNT` — normal user accounts only, excludes machine accounts).
- Note: the LDAP path uses `(&(objectClass=user)(objectCategory=person))` to exclude computers. The `0x10` mask achieves the same filtering at the SAMR level since computer accounts have `UF_WORKSTATION_TRUST_ACCOUNT` (`0x1000`), not `0x10`.
- Returns sorted list of sAMAccountName strings.

Key SAMR fields mapping for policy:
- `DomainPasswordInformation` (level 1): `MinPasswordLength`, `PasswordHistoryLength`, `PasswordProperties`
- `DomainLockoutInformation` (level 12): `LockoutThreshold`, `LockoutDuration`, `LockoutObservationWindow`

Note: `PasswordHistoryLength` is available from SAMR but intentionally excluded from the returned `DomainPolicy` — that dataclass does not carry this field, and neither the LDAP path nor the spray engine uses it. Do not add it.

### Shared utility extraction

Move `to_minutes()` from `ad_spray/ldap/connection.py` to `ad_spray/constants.py` (already exists) so both LDAP and RPC code can use it without circular imports. Update the import in `connection.py`. Also update `ad_spray/ldap/__init__.py` which currently re-exports `to_minutes` from `connection` — change it to re-export from `ad_spray.constants` instead (or via the updated `connection` passthrough) so the public API is preserved.

### Previous anonymous bind workaround

Keep the `_auth_params()` anonymous bind logic and the `is None` checks in `cli.py` from the previous commits. They're harmless and still useful if someone explicitly passes empty creds without `--null-session`.

## Affected Components

- `ad_spray/cli.py`: Add `--null-session` flag to `get-policy` and `get-users` parsers. Add early-return branch in `cmd_get_policy` / `cmd_get_users` that validates only `-d`, passes `args.port` through, calls the RPC function, and returns — keeping the existing LDAP validation path unchanged.
- `ad_spray/rpc/__init__.py`: New file. Empty init for rpc package.
- `ad_spray/rpc/samr.py`: New file. `fetch_policy_rpc(dc_host, port)` and `fetch_users_rpc(dc_host, port)` using impacket SAMR via null SMB session. Includes `_large_int_to_minutes()` helper to extract raw int from impacket `LARGE_INTEGER` structs before delegating to `to_minutes()`.
- `ad_spray/constants.py`: Add `to_minutes()` utility moved from `ldap/connection.py`.
- `ad_spray/ldap/connection.py`: Remove local `to_minutes` definition, import from `ad_spray.constants` instead.
- `ad_spray/ldap/__init__.py`: Update `to_minutes` re-export to source from `ad_spray.constants` (or via the updated `connection.py` passthrough).

## Execution Notes (2026-04-04)

All plan items implemented. Deviations and extras:

- **`_print_policy` / `_save_users` helpers**: Extracted shared display/save logic from `cmd_get_policy` and `cmd_get_users` into private helpers to avoid duplicating code between the null-session and LDAP paths.
- **SAMR `LARGE_INTEGER` turned out to be `NDRHYPER`**: Impacket 0.11.0 represents `LockoutDuration` and `LockoutObservationWindow` as `NDRHYPER` (64-bit int via `['Data']`), not a two-field `LARGE_INTEGER` struct. `_ndrhyper_to_minutes()` handles both access patterns.
- **`USER_NORMAL_ACCOUNT`**: Used impacket's `samr.USER_NORMAL_ACCOUNT` constant (value `0x10`) instead of a raw literal.
- **Pagination**: `fetch_users_rpc` handles `STATUS_MORE_ENTRIES` (`0x00000105`) for domains with large user counts.
