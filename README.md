# AD Password Spray Tools

Password spraying against Active Directory with lockout awareness.

## Features

- **Lockout-aware** - Fetches domain lockout policy and throttles attempts accordingly (n-1 attempts, then sleeps m+1 minutes)

- **Password policy filtering** - Skips passwords that don't meet minimum length or complexity requirements

- **Session management** - Spray state persists to disk. Pause with Ctrl+C, resume anytime with `--resume`. List, export, or delete sessions.

- **Auto-enumeration** - Pulls users and policy from AD automatically, or supply your own user list

- **Live status** - Progress bar with ETA and sleep countdown

## Usage

```bash
pip install ldap3

./spray.py spray -d 10.0.0.1 -w CORP -u admin -p 'P@ss' --passwords passwords.txt
./spray.py spray --resume <session_id>
./spray.py sessions
./spray.py export <session_id>
```

Output: `valid_creds.txt`