# FCP Quick Start Guide

**Time to complete:** 30-60 minutes
**Skill level:** Beginner

---

## Prerequisites Checklist

Before you begin, ensure you have:

- [ ] macOS 12+, Linux (Ubuntu 20.04+), or Windows 10+
- [ ] 4 GB RAM minimum
- [ ] Internet connection
- [ ] Terminal access (Command Prompt on Windows)

---

## Step 1: Install Rust (5 minutes)

### macOS / Linux

Open Terminal and run:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

When prompted, select option `1` (default installation).

After installation completes:

```bash
# Close and reopen your terminal, then run:
rustup default nightly
rustup update
```

### Windows

1. Download rustup-init.exe from https://rustup.rs
2. Run the installer
3. Open Command Prompt and run:

```cmd
rustup default nightly
rustup update
```

### Verify Installation

```bash
rustc --version
# Expected: rustc 1.85.0-nightly (or newer)

cargo --version
# Expected: cargo 1.85.0-nightly (or newer)
```

---

## Step 2: Install Tailscale (5 minutes)

### macOS

```bash
brew install tailscale
```

Or download from: https://tailscale.com/download/mac

### Linux (Ubuntu/Debian)

```bash
curl -fsSL https://tailscale.com/install.sh | sh
```

### Windows

Download from: https://tailscale.com/download/windows

### Authorize Tailscale

```bash
# macOS/Linux
sudo tailscale up

# Windows (run as Administrator)
tailscale up
```

A browser window will open. Sign in with your account (Google, Microsoft, or GitHub).

### Verify

```bash
tailscale status
# Should show your machine as "online"
```

---

## Step 3: Clone Repository (2 minutes)

```bash
git clone https://github.com/joyshmitz/flywheel_connectors.git
cd flywheel_connectors
```

---

## Step 4: Build the Project (10-15 minutes)

```bash
# Quick check (faster, finds errors without full build)
cargo check --workspace

# Full build (required for running)
cargo build --release
```

**Expected output:** Build completes with some warnings (warnings are OK).

---

## Step 5: Verify Installation (2 minutes)

```bash
# Check CLI is available
./target/release/fcp --help

# Run basic diagnostics
./target/release/fcp doctor
```

---

## Step 6: Set Up a Connector (10 minutes)

### Example: Telegram Bot

**Step 6.1:** Create a Telegram bot

1. Open Telegram and search for `@BotFather`
2. Send `/newbot`
3. Follow prompts to name your bot
4. Copy the token provided (format: `123456789:ABCdefGHI...`)

**Step 6.2:** Create configuration directory

```bash
mkdir -p ~/.fcp/connectors
```

**Step 6.3:** Create configuration file

```bash
cat > ~/.fcp/connectors/telegram.toml << 'EOF'
[connector]
name = "telegram"
zone = "z:work"

[credentials]
token = "YOUR_BOT_TOKEN_HERE"

[options]
poll_timeout = 30
EOF
```

**Step 6.4:** Edit the file and replace `YOUR_BOT_TOKEN_HERE` with your actual token.

---

## Step 7: Test the Connector (5 minutes)

### Check connector status

```bash
./target/release/fcp connector list
```

### Run connector introspection

```bash
./target/release/fcp connector introspect telegram
```

This shows available operations and their parameters.

---

## Step 8: View Audit Logs (2 minutes)

```bash
./target/release/fcp audit tail --zone z:work --limit 5
```

This shows recent operations in the work zone.

---

## What's Next?

### Learn More
- Read the full [User Guide](USER_GUIDE_UK.md)
- Read the [FCP Specification](../../FCP_Specification_V2.md)

### Set Up More Connectors
- See [Configuration Examples](CONFIGURATION_EXAMPLES.md)

### Troubleshoot Issues
- See [Troubleshooting Guide](TROUBLESHOOTING.md)

---

## Quick Reference

| Command | Purpose |
|---------|---------|
| `fcp doctor` | System diagnostics |
| `fcp connector list` | List connectors |
| `fcp connector introspect <name>` | Show connector details |
| `fcp audit tail --zone <zone>` | View recent operations |
| `fcp explain --request <id>` | Explain a denied operation |

---

## Getting Help

If you encounter issues:

1. Check the [Troubleshooting Guide](TROUBLESHOOTING.md)
2. Run `fcp doctor` for diagnostics
3. Check the project's GitHub Issues

---

*Last updated: 2026-01-27*
