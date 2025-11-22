## 1. Overview

A simulated SSH brute force attack was performed against a Windows 10 host in a lab environment. The attack generated approximately **30,000 failed logon attempts** over ~5 minutes. Windows Security logs (EventCode 4625) were forwarded to Splunk,
where a detection query and alert were used to identify the abnormal authentication pattern.

This incident was intentionally generated for training and portfolio purposes.

## 2. Environment

- **Attacker**: Kali Linux VM (Hydra)
- **Target**: Windows 10 VM with OpenSSH Server enabled
- **SIEM**: Splunk Enterprise
- **Forwarder**: Splunk Universal Forwarder on Windows
- **Logging**: Windows Security EventLog + Sysmon

## 3. Timeline

- **2200** — Lab environment ready, Splunk receiving Security logs
- **2209** — Hydra SSH brute force started from Kali
- **2213** — First 4625 events observed in Splunk
- **2215** — ~30k failed logons accumulated on the Windows host
- **2220** — Splunk brute force detection query returns results and alert triggers
- **2222** — Attack manually stopped

## 4. Indicators

### Windows Event Logs

- **EventCode**: 4625 (*An account failed to log on*)
- **Status**: `0xC000006D` (Bad username/password)
- **SubStatus**: `0xC0000064` or similar (invalid user) depending on case
- **Caller Process Name**: `C:\Windows\System32\OpenSSH\sshd.exe`

These fields indicate that there have been repeated failed SSH authentication attempts against the system.

## 5. Detection Logic

### SPL Query

```spl
source="WinEventLog:Security" EventCode=4625 | stats count by host | where count > 10
```
## 6. MITRE ATT&CK Mapping

- T1110 – Brute Force
- T1021.004 – Remote Services: SSH
- TA0006 – Credential Access
- TA0001 – Initial Access

## 7. Impact

- High-volume authentication failures created noise in log telemetry.
- No successful SSH authentication recorded.
- No further suspicious activity or lateral movement observed.
- This would indicate automated brute-force activity or credential stuffing.

## 8. Recommendations

- Enforce account lockout policies for repeated failed logons
- Restrict SSH access to trusted IP ranges
- Implement MFA where possible
- Monitor spikes in EventCode 4625
- Add rate-limiting or IDS rules for repeated SSH failures
- Disable SSH if not needed
