# AD Spray

Password spraying tool for Active Directory with lockout protection.

## Features

- **Lockout-aware** - Auto-fetches domain policy, throttles to n-1 attempts per window
- **Auto-enumeration** - Pulls users and password policy from AD, or use custom lists
- **Password filtering** - Skips passwords that don't meet length/complexity requirements
- **Session persistence** - Pause with Ctrl+C, resume anytime
- **Business hours** - Schedule reduced attempts or pause during work hours
- **Clean output** - Status bar shows current credential and ETA; detailed logs saved to session

## Install

```bash
pip install ldap3
```

## Usage

```bash
# Basic spray (auto-fetches users and policy from AD)
ad_spray spray -d dc01.corp.local -w CORP -u admin -p 'P@ss' --passwords wordlist.txt

# With config file
ad_spray spray -c config.ini

# Resume interrupted session
ad_spray spray --resume

# Manual policy (no AD creds needed)
ad_spray spray -d 10.0.0.1 -w CORP --users users.txt --passwords passwords.txt \
    --lockout-threshold 5 --lockout-window 30

# Business hours scheduling
ad_spray spray -c config.ini --timezone America/New_York --business-hours-reduction 2
```

## Session Management

```bash
ad_spray sessions              # List all sessions
ad_spray spray --resume        # Resume (interactive selection)
ad_spray spray --resume <id>   # Resume specific session
ad_spray export <id>           # Export valid credentials
ad_spray delete <id>           # Delete session
```

## Output

- **Screen**: Valid credentials + status bar (current test, ETA, progress)
- **Session dir** (`~/.adspray/sessions/<id>/`):
  - `valid_creds.txt` - Found credentials
  - `spray_log.txt` - Detailed output log
  - `attempts.jsonl` - All attempts (JSON lines)

## Config File

See sample configs in `config/` directory.
