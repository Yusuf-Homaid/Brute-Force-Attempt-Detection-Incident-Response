
# 🚨 Incident Response: Brute Force Attempts Against Virtual Machines

## Scenario Context

As a cybersecurity analyst monitoring virtual machines hosted in **Microsoft Azure**, I observed numerous failed login attempts targeting various VMs across the environment. Many of these attempts originated from suspicious public IP addresses and exhibited brute force characteristics.

My goal was to investigate these activities, determine the risk level, and initiate mitigation steps in line with **NIST 800-61** guidelines.

---

## 🔍 Objective

**Detect and Mitigate Brute Force Attempts Against Azure VMs**  
Implement a **Sentinel Scheduled Query Rule** using **KQL** to identify suspicious repeated failed login attempts and determine if any led to successful access.

---

## 🖥️ Platforms and Tools

- Microsoft Sentinel  
- Microsoft Defender for Endpoint  
- Kusto Query Language (KQL)  
- Microsoft Azure VMs  

---

## 🧽 Incident Response Phases

### 🧰 1. Preparation

**Policies and Procedures**:
- Established protocols to detect and respond to brute force attacks.
- Created procedures for isolation, escalation, and logging of suspicious logins.

**Access Control and Logging**:
- Enabled audit logs for login events in Azure.
- Integrated logs with Microsoft Sentinel for centralized visibility and correlation.

**Training**:
- Provided internal training on brute force and RDP exposure risks.

**Communication Plan**:
- Defined escalation paths for alerts involving privileged accounts and external RDP attempts.

---

### 🔍 2. Detection & Analysis

#### 📊 Observations

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10
```

![Screenshot 2025-04-17 220215](https://github.com/user-attachments/assets/9ac1d292-5a97-4f41-b2a9-b3c9fa5b7d56)



#### 🗛️ Key Findings

| Remote IP         | Action Type | Device Name                                                           | Event Count |
|------------------|-------------|------------------------------------------------------------------------|-------------|
| 170.64.231.251   | LogonFailed | linux-vm-sam.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net       | 101         |
| 10.0.0.8         | LogonFailed | linux-vm-scan-lab-test-marvin.p2zfvso05mlezjev3ck4vqd3kd.cx.internal   | 101         |
| 170.64.231.251   | LogonFailed | slremnuxmain3.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net      | 101         |
| 128.199.21.114   | LogonFailed | slremnuxmain3.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net      | 100         |
| 95.143.191.159   | LogonFailed | onboarding1                                                            | 100         |
| 10.0.0.8         | LogonFailed | danielle-linux-vm1.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net | 99          |
| 45.92.177.109    | LogonFailed | edr-russo                                                              | 96          |
| 45.92.177.109    | LogonFailed | mde-ron                                                                | 96          |
| 10.0.0.8         | LogonFailed | windowsservervm                                                       | 88          |
| 4.240.63.212     | LogonFailed | britt-windows10                                                        | 78          |
| 10.0.0.8         | LogonFailed | vm-final-projec                                                        | 66          |

#### 🔎 Follow-up Investigation

```kql
DeviceLogonEvents
| where RemoteIP in ("170.64.231.251", "10.0.0.8", "128.199.21.114", "95.143.191.159", "45.92.177.109", "4.240.63.212")
| where ActionType == "LogonSuccess"
```
![image](https://github.com/user-attachments/assets/6e38269c-cabe-47b3-bdfb-8e7e635e6159)


**📌 Result**: Successful logons were found from some IPs involved in the brute force attempts, confirming **partial compromise risk**.

![Screenshot 2025-04-17 221506](https://github.com/user-attachments/assets/2187203f-3501-4c68-9caf-50fbf01da626)


![Screenshot 2025-04-17 221731](https://github.com/user-attachments/assets/b2173f6d-dfb9-42eb-9686-f131d2e4f242)


```kql
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where DeviceName in ("linux-vm-sam.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net", "linux-vm-scan-lab-test-marvin.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net", "slremnuxmain3.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net", "slremnuxmain3.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net", "onbourding1", "danielle-linux-vm1.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net", "edr-russo", "mde-ron", "windowsservervm", "britt-windows10", "vm-final-projec"
    ) and RemoteIP in("170.64.231.251", "10.0.0.8", "170.64.231.251", "128.199.21.114", "95.143.191.159", "10.0.0.8", "45.92.177.109", "45.92.177.109", "10.0.0.8", "4.240.63.212", "10.0.0.8")
| summarize EventCount = count() by RemoteIP, ActionType, DeviceName 
| order by EventCount desc 
```

![Screenshot 2025-04-17 225343](https://github.com/user-attachments/assets/c5adf8d3-808b-4296-ab9c-4dc424dd4d7b)



---

### 🛡️ 3. Containment

- **Device Isolation**: Affected VMs were isolated using Microsoft Defender for Endpoint.
  ![Screenshot 2025-04-17 222739](https://github.com/user-attachments/assets/44a9d6b0-4ef7-4e34-a5d5-7f9d784ba152)


![Screenshot 2025-04-17 222803](https://github.com/user-attachments/assets/a159b2e9-f5c4-447e-91e6-521783887b8e)

 
- **NSG Updates**:
  - Blocked RDP access from public internet.
  - RDP access restricted to analyst's home IP.
    ![Screenshot 2025-04-17 225804](https://github.com/user-attachments/assets/e6634f78-1b58-4aa2-8475-4b57676e2af0)


**Policy Proposal**:
- Enforce private RDP access across all VMs.
- Use **Azure Bastion** as a secure RDP alternative.

---

### 🧹 4. Eradication & Recovery

- Reset passwords for accounts associated with successful logons.
- Enabled **MFA** for critical and administrative accounts.
- Updated **Threat Intelligence** with IOCs for perimeter defenses.

---

### 📘️ 5. Post-Incident Activity

**Lessons Learned**:
- Brute force remains a persistent threat when public RDP is exposed.
- MFA and strict NSG rules are essential.

**System Improvements**:
- Automated alert rules will now isolate devices on high failed login counts.
- Enhanced monitoring for off-hours RDP login attempts.

**Documentation**:
- All findings, IOCs, and actions recorded.
- Recommendations presented to IT leadership.

---

## ⚙️ Steps to Create an Alert Rule in Microsoft Sentinel

1. Go to **Microsoft Sentinel** via Azure Portal.
2. Select your **Sentinel Workspace**.
3. Navigate to **Configuration > Analytics**.
4. Click **Create ➕ > Scheduled Query Rule**.
   ![Screenshot 2025-04-17 220221](https://github.com/user-attachments/assets/c2fdce15-fdde-401e-aa51-9b3187e1dfa7)

6. Fill in rule details:
![Screenshot 2025-04-17 220659](https://github.com/user-attachments/assets/b23b9400-b2f7-4286-9d5d-61a6a80c73c4)

   - **Name**: 🔥 *Yusuf- Create-rule alert (Brute Force Attemp Detection) *
   - **Description**: Identifies 50+ failed login attempts from the same IP within 5 hours.
   - **Severity**: 🚨 Medium 
   - **MITRE ATT&CK Tactics**: 🎯 Initial Access, 🔑 Credential Access
  ![Screenshot 2025-04-17 221219](https://github.com/user-attachments/assets/2bfdebc6-8dcd-47a3-9c7b-b37913c5b49e)
![Screenshot 2025-04-17 221304](https://github.com/user-attachments/assets/c607319f-68a9-4410-b686-72cc4ea45cf0)


---

## 🚫 Outcome

- **Attack Status**: Brute force partially successful.
- **Recommendations**: 
  - Block external RDP  
  - Enforce MFA  
  - Harden NSG configurations across all VMs

**✅ Status**: Incident contained. Policy updates and detection improvements implemented.
