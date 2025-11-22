## Overview

This lab simulates an SSH brute force attack against a Windows 10 host, collects Windows Security logs in Splunk, and builds a detection that identifies abnormal volumes of failed logon attempts (EventCode 4625). The goal is to mimic Tier 1 SOC work: see an attack, detect it in logs, and trigger an alert.

## Lab Architecture

- **Attacker:** Kali Linux VM running Hydra
- **Target:** Windows 10 VM (OpenSSH Server enabled)
- **SIEM:** Splunk Enterprise on the host machine
- **Log Forwarder:** Splunk Universal Forwarder on the Windows VM
- **Endpoint Logging:** Sysmon + Windows Security logs

Diagram (rough idea):

Attacker (Kali) -> SSH -> Windows VM -> Universal Forwarder -> Splunk

## Attack Simulation

I used Hydra from Kali to brute force SSH credentials on the Windows VM.

Example command:

```bash
hydra -l <username> -P /usr/share/wordlists/rockyou.txt.gz ssh://<windows-ip>
