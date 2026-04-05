<!-- Review 1 completed: 2026-04-04 -->
# Plan: Allow `--userpass` without `--passwords`

## Summary

Allow `--userpass` to be used as the sole spray mode without requiring a `--passwords` file. When `--userpass` is set and `--passwords` is not provided, the spray session is created with an empty password list and only the user-as-password phase runs.

## Problem

Currently, `--passwords` is validated as required before the spray session is created (`cli.py:187-189`). Even if the user only wants to try username-as-password, they must provide a passwords file. This is unnecessary friction — a common first pass in an engagement is just `--userpass` with no password list.

## Goal

- `python3 spray.py spray -d dc01 -w CORP --users users.txt --userpass --lockout-window 5 --attempts 1` works without `--passwords`.
- When `--passwords` is omitted and `--userpass` is set, the password list is empty — only the userpass phase runs, then the session completes.
- When both `--passwords` and `--userpass` are provided, behavior is unchanged (userpass phase + password list spray).
- When neither is provided, the existing error is shown.

## Design

### CLI validation (`ad_spray/cli.py`)

Change the `--passwords` validation (line 187-189) to only require `--passwords` when `--userpass` is not set:

```python
if not args.spray_passwords and not args.userpass:
    print(f"{Colors.RED}[!] --passwords or --userpass is required{Colors.NC}", file=sys.stderr)
    return 1
```

When `--passwords` is not provided, skip the file loading block (lines 204-214) and set `passwords = []`.

### Engine (`ad_spray/engine.py`)

The engine mostly handles an empty password list correctly:
- The userpass phase runs when `config.user_as_pass` is True (line 466).
- The main password loop iterates `valid_passwords` which will be empty — the loop body simply doesn't execute.
- Completion is marked at line 549 as normal.

One fix needed: after the userpass phase (lines 492-496), `attempts_since_sleep` is incremented and `_should_sleep()` fires unconditionally. With an empty password list and `--attempts 1`, this triggers a full lockout-window sleep right before the empty main loop completes immediately. Guard the post-userpass sleep so it only fires when there are passwords remaining:

```python
if not self.stopped and valid_passwords:
    self.session.attempts_since_sleep += 1
    if self._should_sleep():
        self._update_status_bar(extra=f"Sleeping {sleep_time // 60}m")
        self._do_sleep(sleep_time)
```

### Session creation

No changes needed. `create_session` accepts an empty passwords list.

## Affected Components

- `ad_spray/cli.py`: Relax `--passwords` validation when `--userpass` is set. Skip password file loading when `--passwords` is absent. Adjust the "Loaded N users" message to also show the spray mode. Add a `--userpass`-only example to the spray epilog.
- `ad_spray/engine.py`: Guard post-userpass sleep to only fire when `valid_passwords` is non-empty (avoids a wasted lockout-window sleep when no password list is provided).

## Execution Notes

Executed: 2026-04-04

All plan items implemented with no deviations:

1. `ad_spray/cli.py`: Relaxed `--passwords` validation to accept `--userpass` as alternative. Wrapped password file loading in `if args.spray_passwords` with `else: passwords = []`. Updated loaded-users message to show spray mode. Added userpass-only example to epilog.
2. `ad_spray/engine.py`: Added `valid_passwords` guard to post-userpass sleep to avoid wasted lockout-window delay when no password list is provided.
