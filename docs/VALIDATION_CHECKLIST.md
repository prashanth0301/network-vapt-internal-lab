# Lab Validation Checklist

## Phase 1 — Virtual Lab Setup Verification

---

## Instructions

1. Execute each test in order
2. Check the box when the test passes
3. Note any failures and reference the Troubleshooting Guide
4. Run this checklist **before starting Phase 2**

---

## 1. Hypervisor Validation

### 1.1 VirtualBox Installation (if using VirtualBox)
- [ ] VirtualBox installed (version 7.x+)
- [ ] `VBoxManage --version` returns a version number
- [ ] Host Network Manager shows `vboxnet0` adapter
- [ ] DHCP server is **disabled** for vboxnet0
- [ ] Host-Only adapter IP: `192.168.56.1` / `255.255.255.0`

### 1.2 VMware Workstation (if using VMware)
- [ ] VMware Workstation installed
- [ ] Virtual Network Editor shows host-only network (e.g., VMnet2)
- [ ] Subnet: `192.168.56.0/255.255.255.0`
- [ ] DHCP is **disabled**

---

## 2. VM Validation

### 2.1 Kali Linux
- [ ] VM boots successfully into graphical desktop
- [ ] Login with `vapt` / `vapt@lab2024` succeeds
- [ ] `ip a` shows `192.168.56.10/24` on eth0
- [ ] `nmap --version` → output contains "Nmap version 7.9x+"
- [ ] `msfconsole --version` → output contains "Framework Version"
- [ ] `tshark --version` → output contains "TShark"
- [ ] `python3 --version` → Python 3.11+
- [ ] `git --version` → Git 2.x+

### 2.2 Metasploitable2
- [ ] VM boots successfully (console login prompt appears)
- [ ] Login with `msfadmin` / `msfadmin` succeeds
- [ ] `ifconfig eth0` shows `192.168.56.20`
- [ ] Web server responds: `curl -I http://192.168.56.20` → `200 OK`
- [ ] SSH responds: `ssh msfadmin@192.168.56.20` → login successful
- [ ] FTP responds: `ftp 192.168.56.20` (anonymous login)

### 2.3 Windows 7
- [ ] VM boots into Windows 7 desktop
- [ ] Login with `admin` / `Password123!` succeeds
- [ ] `ipconfig` shows `192.168.56.30`
- [ ] Firewall is disabled (`netsh advfirewall show allprofiles`)
- [ ] RDP is enabled
- [ ] SMB v1 is enabled
- [ ] UAC is disabled

### 2.4 Ubuntu Server (Optional)
- [ ] VM boots to command-line login prompt
- [ ] Login with `vaptadmin` / `vapt@lab2024` succeeds
- [ ] `ip a` shows `192.168.56.40/24`
- [ ] SSH enabled: `ssh vaptadmin@192.168.56.40` → login successful
- [ ] Apache running: `curl -I http://192.168.56.40` → `200 OK`

---

## 3. Connectivity Validation

### 3.1 From Kali Linux → Host Machine
- [ ] `ping -c 3 192.168.56.1` → 0% packet loss

### 3.2 From Kali Linux → Metasploitable2
- [ ] `ping -c 3 192.168.56.20` → 0% packet loss
- [ ] `ssh msfadmin@192.168.56.20` → login successful
- [ ] `curl -I http://192.168.56.20` → `HTTP/1.1 200 OK`
- [ ] `nmblookup -A 192.168.56.20` → NetBIOS name resolves

### 3.3 From Kali Linux → Windows 7
- [ ] `ping -c 3 192.168.56.30` → 0% packet loss
- [ ] `smbclient -L //192.168.56.30 -N` → shares listed (or access denied is acceptable)

### 3.4 From Kali Linux → Ubuntu Server (if deployed)
- [ ] `ping -c 3 192.168.56.40` → 0% packet loss

### 3.5 Nmap Host Discovery (comprehensive)
- [ ] `nmap -sn 192.168.56.0/24` → All VMs appear as "Host is up"

**Expected output (VirtualBox):**
```
Nmap scan report for 192.168.56.1
Host is up.
Nmap scan report for 192.168.56.10
Host is up.
Nmap scan report for 192.168.56.20
Host is up.
Nmap scan report for 192.168.56.30
Host is up.
```

---

## 4. Tool Validation (from Kali)

- [ ] `nmap -sV 192.168.56.20` → service versions detected
- [ ] `nmap -O 192.168.56.20` → OS detected (Linux 2.6.x)
- [ ] `nmap -p 1-1000 192.168.56.20` → open ports detected
- [ ] `nmap -sU --top-ports 20 192.168.56.20` → UDP ports sweep works

---

## 5. Snapshot Validation

- [ ] `VBoxManage snapshot "Kali Linux" list` → contains "Clean Installation"
- [ ] `VBoxManage snapshot "Metasploitable2" list` → contains "Clean Installation"
- [ ] `VBoxManage snapshot "Windows 7" list` → contains "Clean Installation"
- [ ] (If deployed) `VBoxManage snapshot "Ubuntu Server" list` → contains "Clean Installation"

---

## 6. Final Sign-off

| Check | Status |
|-------|--------|
| All pings pass | [ ] |
| SSH to Metasploitable2 works | [ ] |
| HTTP to Metasploitable2 works | [ ] |
| Windows 7 reachable | [ ] |
| Nmap host discovery finds all targets | [ ] |
| Nmap port scan works on targets | [ ] |
| Clean snapshots created for all VMs | [ ] |
| All screenshots captured to `screenshots/phase-1-lab-setup/` | [ ] |

**Lab Setup Validated By:** _________________  
**Date:** _________________  
**Lab Ready for Phase 2:** [ ] Yes [ ] No
