# FCP Troubleshooting Guide

This guide helps you diagnose and resolve common issues with FCP.

---

## Quick Diagnostics

Always start with:

```bash
./target/release/fcp doctor
```

This checks:
- Tailscale connectivity
- Zone configuration
- Checkpoint freshness
- Revocation status

---

## Common Issues

### Issue 1: Build Fails

#### Symptom
```
error[E0658]: use of unstable library feature
```

#### Cause
Rust nightly is not active or is outdated.

#### Solution
```bash
# Ensure nightly is default
rustup default nightly

# Update toolchain
rustup update nightly

# Verify
rustc --version
# Should show: rustc 1.85.0-nightly or newer
```

---

### Issue 2: Tailscale Not Connected

#### Symptom
```
fcp doctor
Error: Tailscale not connected
```

#### Cause
Tailscale daemon is not running or not authorized.

#### Solution
```bash
# Check Tailscale status
tailscale status

# If not running, start it:
# macOS
sudo tailscaled &
tailscale up

# Linux
sudo systemctl start tailscaled
tailscale up

# Verify connection
tailscale status
# Should show your machine as "online"
```

---

### Issue 3: Connector Not Found

#### Symptom
```
fcp connector list
Error: No connectors found
```

#### Cause
Configuration files are missing or in wrong location.

#### Solution
```bash
# Check configuration directory
ls -la ~/.fcp/connectors/

# If empty, create configuration:
mkdir -p ~/.fcp/connectors/
# Then create connector config files (see CONFIGURATION_EXAMPLES.md)

# Verify file permissions
chmod 600 ~/.fcp/connectors/*.toml
```

---

### Issue 4: Authentication Failed

#### Symptom (Twitter)
```
Error: Unauthorized - Failed to get authenticated user
```

#### Symptom (Telegram)
```
Error: Unauthorized - Invalid bot token
```

#### Cause
Credentials are incorrect or expired.

#### Solution

**For Twitter:**
1. Go to https://developer.twitter.com/
2. Verify your app credentials
3. Regenerate tokens if needed
4. Update `~/.fcp/connectors/twitter.toml`

**For Telegram:**
1. Message @BotFather on Telegram
2. Send `/mybots` to verify your bot
3. Use `/token` to get a new token if needed
4. Update `~/.fcp/connectors/telegram.toml`

**For Discord:**
1. Go to https://discord.com/developers/applications
2. Select your application
3. Go to "Bot" section
4. Click "Reset Token" to get a new one
5. Update `~/.fcp/connectors/discord.toml`

---

### Issue 5: Capability Denied

#### Symptom
```
fcp invoke telegram send_message ...
Error: Missing capability 'telegram.write' for zone 'z:work'
```

#### Cause
The connector doesn't have the required capability for the zone.

#### Solution

1. Check current capabilities:
```bash
./target/release/fcp connector introspect telegram
```

2. Verify the capability is in the config:
```toml
# In ~/.fcp/connectors/telegram.toml
[capabilities]
required = ["telegram.read", "telegram.write"]
```

3. Ensure the zone allows this capability:
```bash
./target/release/fcp explain --request <request-id>
```

---

### Issue 6: Rate Limited

#### Symptom (Twitter)
```
Error: Rate limited - Too Many Requests (429)
Retry-After: 900
```

#### Cause
You've exceeded the API rate limits.

#### Solution
1. Wait for the retry period (shown in seconds)
2. Implement rate limiting in your usage:
   - Twitter: 300 requests/15 min (read), 200 tweets/15 min (write)
   - Telegram: 30 messages/second
   - Discord: Varies by endpoint

3. Check rate limit status:
```bash
./target/release/fcp audit tail --zone z:work --filter "rate_limit"
```

---

### Issue 7: Connection Timeout

#### Symptom
```
Error: External service timeout after 30s
```

#### Cause
Network issues or service is down.

#### Solution
1. Check your internet connection
2. Check service status:
   - Twitter: https://api.twitterstat.us/
   - Telegram: https://downdetector.com/status/telegram/
   - Discord: https://discordstatus.com/

3. Increase timeout in config:
```toml
[options]
timeout_secs = 60  # Increase from default 30
```

---

### Issue 8: Invalid Configuration

#### Symptom
```
Error: Invalid configuration: missing field 'token'
```

#### Cause
Configuration file is malformed or missing required fields.

#### Solution
1. Validate TOML syntax:
```bash
# Install toml-cli if needed
cargo install toml-cli

# Validate file
toml ~/.fcp/connectors/telegram.toml
```

2. Compare with examples in `CONFIGURATION_EXAMPLES.md`

3. Check for common mistakes:
   - Missing quotes around strings
   - Incorrect indentation
   - Typos in field names

---

### Issue 9: Zone Mismatch

#### Symptom
```
Error: Zone mismatch - connector bound to z:private, request from z:work
```

#### Cause
Trying to use a connector from a different zone.

#### Solution
1. Check connector's zone:
```bash
./target/release/fcp connector show telegram
# Zone: z:private
```

2. Either:
   - Change the connector's zone in config
   - Use the correct zone in your request

```toml
# In connector config
[connector]
zone = "z:work"  # Change to match your needs
```

---

### Issue 10: Audit Log Full

#### Symptom
```
Warning: Audit log disk usage high (>90%)
```

#### Cause
Audit logs accumulated over time.

#### Solution
1. Check disk usage:
```bash
du -sh ~/.fcp/audit/
```

2. Configure retention in global config:
```toml
# In ~/.fcp/config.toml
[audit]
retention_days = 7  # Reduce from default 30
```

3. Manually clean old logs if needed:
```bash
# Remove logs older than 7 days
find ~/.fcp/audit/ -mtime +7 -delete
```

---

## Diagnostic Commands

### System Health

```bash
# Full system check
./target/release/fcp doctor

# Verbose output
./target/release/fcp doctor --verbose
```

### Connector Status

```bash
# List all connectors
./target/release/fcp connector list

# Detailed connector info
./target/release/fcp connector show telegram

# Test connector connectivity
./target/release/fcp connector test telegram
```

### Audit Logs

```bash
# Recent operations
./target/release/fcp audit tail --zone z:work --limit 20

# Filter by connector
./target/release/fcp audit tail --zone z:work --connector telegram

# Filter by result
./target/release/fcp audit tail --zone z:work --filter "error"

# Specific time range
./target/release/fcp audit tail --zone z:work --since "1h"
```

### Decision Explanation

```bash
# Explain why operation was denied
./target/release/fcp explain --request <request-id>

# Get request ID from audit log
./target/release/fcp audit tail --zone z:work --limit 1 --format json
```

---

## Getting More Help

### Log Levels

Increase verbosity for debugging:

```bash
# Set environment variable
export FCP_LOG_LEVEL=debug

# Or in config
[general]
log_level = "debug"  # trace, debug, info, warn, error
```

### Debug Output

```bash
# Run with trace logging
RUST_LOG=trace ./target/release/fcp connector test telegram
```

### Reporting Issues

When reporting issues, include:

1. FCP version:
```bash
./target/release/fcp --version
```

2. Rust version:
```bash
rustc --version
```

3. Operating system:
```bash
uname -a  # macOS/Linux
# Or Windows version
```

4. Tailscale status:
```bash
tailscale version
tailscale status
```

5. Error message (full output)

6. Relevant configuration (with credentials removed)

---

## Error Code Reference

| Code | Category | Meaning |
|------|----------|---------|
| 1001 | Config | Invalid request format |
| 1002 | Config | Missing required field |
| 1003 | Config | Invalid configuration |
| 1004 | Config | Missing credentials |
| 2001 | Auth | Unauthorized |
| 2002 | Auth | Invalid token |
| 2003 | Auth | Token expired |
| 3001 | Capability | Missing capability |
| 3002 | Capability | Capability revoked |
| 3003 | Capability | Zone mismatch |
| 4001 | External | Service unavailable |
| 4002 | External | Rate limited |
| 4003 | External | Timeout |
| 5001 | Internal | Unexpected error |
| 5002 | Internal | State corruption |

---

*Last updated: 2026-01-27*
