# Splunk Home Lab

## 🧑‍💻Scenarios

### :penguin:Linux scenarios

### Scenario 1: SSH Brute Force attack detection

**MITRE ATT&CK mapping:**
* **Tactic:** Credential Access
* **Technique:** [T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

#### :crossed_swords:Attack Simulation
To simulate a password guessing attack, I used Kali Linux and the `hydra` tool against the Ubuntu server's SSH service. 
A custom password dictionary was utilized to generate multiple authentication failures. 

Kali Linux attack command:
```
hydra -l <ATTACKED_ACCOUNT> -P passwords.txt ssh://<MACHINE_IP>
```
#### :shield:Threat Hunting
SPL Query:
```
source="/var/log/auth.log" sourcetype="linux_secure" "Failed password"
| rex field=_raw "Failed password for (?<user>\S+) from (?<src_ip>[0-9\.]+)"
| stats count by src_ip, user
| where count >= 5
| rename src_ip as "Suspicious IP", user as "Attacked account", count as "Number of failed attempts"
| sort by "Number of failed attempts"
```
#### :bar_chart:Detection in Splunk
<img width="1016" height="225" alt="image" src="https://github.com/user-attachments/assets/1d494132-def6-48fc-b420-7bfa1e003d7c" />

#### :rotating_light:Alerting
Alert configuration:
<img width="945" height="995" alt="image" src="https://github.com/user-attachments/assets/9921f892-224c-405f-9238-01b111baa4dd" />

Triggered alerts:
<img width="945" height="160" alt="image" src="https://github.com/user-attachments/assets/85498caa-e21f-4b0c-b2bc-775098c8ad6a" />


### Scenario 2: OS Credential Dumping

**MITRE ATT&CK mapping:**
* **Tactic:** Credential Access
* **Technique:** [T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow](https://attack.mitre.org/techniques/T1003/008/)

#### :crossed_swords:Attack Simulation
To replicate credential dumping, an unauthorized user attempted to access the restricted `/etc/shadow` file, which contains hashed user passwords. 
This action was monitored by the `auditd` service.

#### :shield:Threat Hunting
SPL Query:
```
source="/var/log/audit.log" type="EXECVE" ("/etc/passwd" OR "/etc/shadow")
| table a0, a1, a2, a3
| rename a0 as "Command, a1 as "Arg 1", a2 as "Arg 2", a3 as "Arg 3"
```

#### :bar_chart:Detection in Splunk
<img width="945" height="227" alt="image" src="https://github.com/user-attachments/assets/6c80dbc5-a475-41d3-9ad3-6a19bab28ece" />

### Scenario 3: Backdoor account creation

**MITRE ATT&CK mapping:**
* **Tactic:** Persistence
* **Technique:** [T1136.001 - Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)

#### :crossed_swords:Attack Simulation
Adversaries may create local accounts to maintain persistent access to victim systems. 
To simulate this, a new user account was added directly via the command line interface using escalated privileges.

#### :shield:Threat Hunting
SPL Query:
```
source="/var/log/audit.log" type="EXECVE" ("useradd" OR "usermod")
| eval Time=strftime(_time, "%Y-%m-%D %H-%M-%S")
| table Time, a0, a1, a2, a3, a4
| rename a0 as "Command", a1 as "Arg 1", a2 as "Arg 2", a3 as "Arg 3" a4 as "Added account"
| sort - Time
```

#### :bar_chart:Detection in Splunk
<img width="945" height="219" alt="image" src="https://github.com/user-attachments/assets/285375cf-8d51-4c05-a2e0-359de668fe12" />




### :window:Windows scenarios

### Scenario 1: Network Logon Brute Force Attack

**MITRE ATT&CK mapping:**
* **Tactic:** Credential Access
* **Technique:** [T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

#### :crossed_swords:Attack Simulation
To trigger network authentication failures (Logon Type 3), a simulated brute-force attack was performed against the Windows machine's SMB service from an external node.

#### :shield:Threat Hunting
SPL Query:
```
source="*WinEventLog:Security" EventCode=4625 Logon_Type=3
| stats count by Account_Name, Source_Network_Address
| rename Account_Name as "Attacked account", Source_Network_Address as "Suspicious IP", count as "Number of failed attempts"
| sort - "Number of failed attempts"
```

#### :bar_chart:Detection in Splunk
<img width="945" height="206" alt="image" src="https://github.com/user-attachments/assets/87926e00-4fa0-4bf0-98d4-6d39442bae86" />


### Scenario 2: Windows Security Event Logs removal

**MITRE ATT&CK mapping:**
* **Tactic:** Defense Evasion
* **Technique:** [T1070.001 - Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)

#### :crossed_swords:Attack Simulation
Adversaries often clear event logs to hide their activities. This was simulated by manually clearing the Security Event Logs using the built-in Windows utility `wevtutil` via Command Prompt.

#### :shield:Threat Hunting
SPL Query:
```
source="*WinEventLog:Security" EventCode=1102
| eval Time=strftime(_time, "%Y-%m-%D %H-%M-%S")
| table Time, Account_Name, ComputerName, EventCode
| rename Account_Name as "Account Name", ComputerName as "Computer Name", EventCode as "Event Code"
```

#### :bar_chart:Detection in Splunk
<img width="945" height="157" alt="image" src="https://github.com/user-attachments/assets/a7f186ea-40a2-43c3-8d9c-da9a9ac89113" />


### Scenario 3: Adding account to security-enabled local group

**MITRE ATT&CK mapping:**
* **Tactic:** Persistence
* **Technique:** [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)

#### :crossed_swords:Attack Simulation
To establish persistent high-level access, a standard user account was added to the local `Administrators` security-enabled group using the Windows command line.

#### :shield:Threat Hunting
SPL Query:
```
source="*WinEventLog:Security" EventCode=4732
| eval Time=strftime(_time, "%Y-%m-%D %H-%M-%S")
| table Time, Account_Name, Group_Name, Security_ID
```

#### :bar_chart:Detection in Splunk
<img width="945" height="202" alt="image" src="https://github.com/user-attachments/assets/26bd6697-bcb8-4d45-a591-6ce03a5ebd71" />
