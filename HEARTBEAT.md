# HEARTBEAT.md - Periodic Security Tasks

Use this file to schedule periodic security checks with ExaAiAgent.

## Recommended Periodic Checks

### Every 6 Hours
- **Quick scan of critical assets:**
  ```bash
  exaai -n --target https://api.production.com --instruction "Quick security check, focus on auth and injection"
  ```

### Daily
- **Full scan of main application:**
  ```bash
  exaai -n --target https://app.example.com
  ```
- **Check for new CVEs affecting your stack:**
  ```bash
  exaai -n --target ./package.json --instruction "Check for known vulnerabilities in dependencies"
  ```

### Weekly
- **GitHub repo security review:**
  ```bash
  exaai -n --target https://github.com/org/main-repo
  ```
- **Cloud configuration audit:**
  ```bash
  exaai -n --target aws --prompt-modules cloud_security
  ```
- **Kubernetes cluster audit:**
  ```bash
  exaai -n --target kubectl --prompt-modules kubernetes_security
  ```

## Heartbeat Checklist

When running periodic checks, the agent should:

1. [ ] Verify Docker is running
2. [ ] Run the scheduled scan in headless mode (`-n`)
3. [ ] Parse `exaai_runs/<latest>/report.json` for findings
4. [ ] Alert user if:
   - Critical or High severity findings detected
   - New vulnerabilities found since last scan
   - Scan failed or timed out
5. [ ] Update memory with scan summary
6. [ ] Skip alert if no new findings (reply `HEARTBEAT_OK`)

## Example Heartbeat Response

**If findings detected:**
```
🚨 Security Alert: ExaAiAgent found 2 High severity issues on api.example.com

1. [HIGH] SQL Injection in /api/users?id=
2. [HIGH] Missing rate limiting on /api/login

Full report: exaai_runs/scan-20260203-1200/report.md
```

**If no issues:**
```
HEARTBEAT_OK
```

## Integration with OpenClaw Cron

To schedule periodic scans, add a cron job:

```yaml
# Example: Daily scan at 9 AM
schedule:
  kind: cron
  expr: "0 9 * * *"
  tz: "Europe/Brussels"
payload:
  kind: agentTurn
  message: "Run ExaAiAgent security scan on https://api.production.com and report findings"
```
