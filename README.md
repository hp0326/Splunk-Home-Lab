# Splunk Home Lab

## 🧑‍💻Scenarios

### :penguin:Linux scenarios

### Scenario 1: SSH Brute Force attack detection

**MITRE ATT&CK mapping:**
* **Tactic:** Credential Access
* **Technique:** [T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

#### :crossed_swords:Attack Simulation
To simulate a password guessing attack, I used Kali Linux and the `hydra` tool against the Ubuntu server's SSH service. 
A custom password dictionary was utilized to generate multiple authentication failures. <br />

Kali Linux attack command:
```
hydra -l <ATTACKED_ACCOUNT> -P passwords.txt ssh://<UBUNTU_IP>
```
SPL Query:
```
source="/var/log/auth.log" sourcetype="linux_secure" "Failed password"
| rex field=_raw "Failed password for (?<user>\S+) from (?<src_ip>[0-9\.]+)"
| stats count by src_ip, user
| where count >= 5
| rename src_ip as "Suspicious IP", user as "Attacked account", count as "Number of failed attempts"
| sort - "Number of failed attempts"
```

### Scenario 2: Credential Dumping

**MITRE ATT&CK mapping:**
* **Tactic:** Credential Access
* **Technique:** [T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow](https://attack.mitre.org/techniques/T1003/008/)

### Scenario 3: Backdoor account creation

**MITRE ATT&CK mapping:**
* **Tactic:** Persistence
* **Technique:** [T1136.001 - Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)



### :window:Windows scenarios

### Scenario 1: SSH Brute Force attack detection

**MITRE ATT&CK mapping:**
* **Tactic:** Credential Access
* **Technique:** [T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

### Scenario 2: Windows Security Event Logs removal

**MITRE ATT&CK mapping:**
* **Tactic:** Defense Evasion
* **Technique:** [T1070.001 - Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)

### Scenario 3: Adding account to security-enabled local group

**MITRE ATT&CK mapping:**
* **Tactic:** Persistence
* **Technique:** [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
