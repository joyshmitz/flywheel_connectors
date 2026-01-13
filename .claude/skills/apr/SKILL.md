---
name: apr
description: Run APR (Automated Plan Reviser) workflow for FCP specification refinement. Use when asked to run APR, revision rounds, spec review, integrate GPT feedback, or harmonize docs. Handles Oracle remote setup, running rounds, integrating feedback, and syncing README/implementation docs.
---

# APR - Automated Plan Reviser for FCP

This skill automates iterative specification refinement using GPT Pro 5.2 Extended Reasoning via Oracle.

## Overview

The Flywheel Connector Protocol (FCP) specification is refined through multiple rounds of GPT Pro review. Each round:
1. Sends README + spec (optionally + implementation) to GPT Pro 5.2
2. Receives detailed revision suggestions with rationale
3. Integrates feedback into the spec via Claude Code
4. Harmonizes README and implementation docs
5. Commits with detailed messages

## Oracle Remote Setup (One-Time)

For headless/SSH environments, Oracle can delegate browser automation to a local machine.

### On the LOCAL machine (with browser/GUI):
```bash
# Install Oracle if needed
npm install -g @steipete/oracle

# Start server (keep this terminal open)
oracle serve --port 9222 --token "flywheel-apr-2026"
```

### On the REMOTE machine (this server):
```bash
# Add to shell config for persistence
echo 'export ORACLE_REMOTE_HOST="100.114.183.31:9222"' >> ~/.zshrc
echo 'export ORACLE_REMOTE_TOKEN="flywheel-apr-2026"' >> ~/.zshrc
source ~/.zshrc

# Test connection
oracle -p "test connection" -e browser -m "5.2 Thinking"
```

**Tailscale IPs for this setup:**
- Mac Mini: `100.114.183.31`
- iMac: `100.81.209.68`
- This server (threadripperje): `100.91.120.17`

## Commands

### Check Status
```bash
cd /data/projects/flywheel_connectors
apr status          # Check Oracle sessions
apr list            # List workflows
apr history         # Show revision history
apr dashboard       # Interactive analytics
```

### Run a Revision Round
```bash
# Standard round (README + spec only)
apr run <N>

# Include implementation doc (every 3-4 rounds)
apr run <N> --include-impl

# First run with manual login (if Oracle not authenticated)
apr run <N> --login --wait

# Preview without sending
apr run <N> --dry-run

# Render prompt for manual paste
apr run <N> --render --output /tmp/prompt.md
```

### View and Compare Rounds
```bash
apr show <N>        # View round output
apr diff <N> <M>    # Compare two rounds
apr diff <N>        # Compare round N vs N-1
```

### Generate Integration Prompt
```bash
apr integrate <N> --copy   # Copy to clipboard
apr integrate <N> --output /tmp/integrate.md
```

## Integration Workflow

After GPT Pro completes a round, integrate the feedback:

### Step 1: Prime Claude Code
Before integrating feedback, ensure full context:
```
First read ALL of AGENTS.md and README.md super carefully. Then use your code
investigation agent to fully understand the project architecture. Read ALL of
FCP_Specification_V2.md and docs/fcp_model_connectors_rust.md.
```

### Step 2: Integrate GPT Pro Feedback
```
Now integrate all of this feedback (and let me know what you think of it,
whether you agree with each thing and how much) from GPT 5.2:

```
<paste GPT Pro output or use: apr show <N>>
```

Be meticulous and use ultrathink.
```

### Step 3: Harmonize README
```
We need to revise the README too for these changes (don't write about these
as "changes" however, make it read like it was always like that, we don't
have any users yet!). Use ultrathink.
```

### Step 4: Harmonize Implementation Doc
```
Now review docs/fcp_model_connectors_rust.md ultra carefully and ensure it
is 100% harmonized with the V2 spec and as optimized as possible subject
to those constraints. Use ultrathink.
```

### Step 5: Commit Changes
```
Based on your knowledge of the project, commit all changed files now in a
series of logically connected groupings with super detailed commit messages
for each and then push. Take your time to do it right. Don't edit the code
at all. Don't commit obviously ephemeral files. Use ultrathink.
```

## After Compaction Recovery

If context compaction occurs, re-prime before continuing:
```
Reread AGENTS.md so it's still fresh in your mind. Also reread the entire
V2 spec so it's fresh before you read docs/fcp_model_connectors_rust.md.
Use ultrathink.
```

## Key Files

| File | Purpose |
|------|---------|
| `FCP_Specification_V2.md` | Main protocol specification (141 KB) |
| `README.md` | Project overview and quick start (44 KB) |
| `docs/fcp_model_connectors_rust.md` | Rust implementation guide (68 KB) |
| `AGENTS.md` | Development rules and guidelines (25 KB) |
| `.apr/rounds/fcp/round_N.md` | GPT Pro outputs for each round |

## Workflow Configuration

The APR workflow is configured in `.apr/workflows/fcp.yaml`:
- **Documents**: README.md, FCP_Specification_V2.md, docs/fcp_model_connectors_rust.md
- **Model**: GPT Pro 5.2 Thinking (Extended Reasoning)
- **Output**: `.apr/rounds/fcp/`

## Tips

1. **Include implementation every 3-4 rounds** - Keeps spec grounded in reality
2. **Don't skip harmonization** - Changes should flow through all docs
3. **Watch for convergence** - Use `apr stats` to see if changes are dampening
4. **Target 15-20 rounds** - For complex protocols, more iterations = better spec
5. **New session per round** - Start fresh GPT Pro conversations to avoid context pollution

## Troubleshooting

### Oracle Connection Issues
```bash
# Check if Oracle server is running on local machine
# On local: oracle serve --port 9222 --token "..."

# Verify Tailscale connectivity
tailscale ping 100.114.183.31

# Test Oracle directly
oracle -p "test" -e browser -m "5.2 Thinking" -v
```

### APR Issues
```bash
# Verbose mode for debugging
apr run <N> -v

# Check workflow config
cat .apr/workflows/fcp.yaml

# Verify files exist
ls -la README.md FCP_Specification_V2.md docs/fcp_model_connectors_rust.md
```
