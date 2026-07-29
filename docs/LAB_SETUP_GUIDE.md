# Virtual Lab Setup Guide

## Phase 1 — Network VAPT Platform

---

## 1. Network Topology Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        HOST MACHINE                                  │
│              (Windows/Linux/macOS with VirtualBox/VMware)            │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                 Host-Only Network (VirtualBox)                │   │
│  │              Internal Network (VMware) — 192.168.56.0/24      │   │
│  │                                                               │   │
│  │  ┌──────────────────┐    ┌──────────────────┐                 │   │
│  │  │   Kali Linux     │    │  Metasploitable2  │                │   │
│  │  │  192.168.56.10   │◄──►│  192.168.56.20    │                │   │
│  │  │  Attacker        │    │  Target 1         │                │   │
│  │  │  RAM: 4 GB       │    │  RAM: 512 MB      │                │   │
│  │  │  CPU: 2 Cores    │    │  CPU: 1 Core      │                │   │
│  │  │  Disk: 60 GB     │    │  Disk: 8 GB       │                │   │
│  │  └──────────────────┘    └──────────────────┘                 │   │
│  │                                                               │   │
│  │  ┌──────────────────┐    ┌──────────────────┐                 │   │
│  │  │   Windows 7       │    │  Ubuntu Server   │                │   │
│  │  │  192.168.56.30    │◄──►│  192.168.56.40   │                │   │
│  │  │  Target 2         │    │  Target 3 (Opt.) │                │   │
│  │  │  RAM: 2 GB        │    │  RAM: 1 GB       │                │   │
│  │  │  CPU: 2 Cores     │    │  CPU: 1 Core     │                │   │
│  │  │  Disk: 40 GB      │    │  Disk: 20 GB     │                │   │
│  │  └──────────────────┘    └──────────────────┘                 │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Host Machine IP (192.168.56.1) — Gateway for Host-Only Net  │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. IP Addressing Plan

| Machine | Role | IP Address | Subnet | Gateway | DNS |
|---------|------|------------|--------|---------|-----|
| Host Machine | Management | 192.168.56.1 | 255.255.255.0 | N/A | N/A |
| Kali Linux | Attacker | 192.168.56.10 | 255.255.255.0 | 192.168.56.1 | 8.8.8.8 |
| Metasploitable2 | Target 1 | 192.168.56.20 | 255.255.255.0 | 192.168.56.1 | 8.8.8.8 |
| Windows 7 | Target 2 | 192.168.56.30 | 255.255.255.0 | 192.168.56.1 | 8.8.8.8 |
| Ubuntu Server | Target 3 (Optional) | 192.168.56.40 | 255.255.255.0 | 192.168.56.1 | 8.8.8.8 |

**Network:** 192.168.56.0/24  
**DHCP:** Disabled (all IPs are static)  
**Isolation:** No internet access via host-only adapter (unless NAT adapter added during installation)

---

## 3. Resource Allocation

### 3.1 Hypervisor Selection

| Feature | VirtualBox (Recommended) | VMware Workstation Pro |
|---------|--------------------------|----------------------|
| License | Free (GPLv2) | Paid |
| Host-Only Network | Yes | Yes |
| Snapshot Support | Yes | Yes |
| Guest Additions | Yes | Yes |
| Export/Import OVA | Yes | Yes |
| CLI Automation (VBoxManage) | Yes | Yes (vmrun) |

**Recommendation:** VirtualBox for cost-effectiveness and broad OS support.

### 3.2 VM Resource Matrix

| VM | vCPU | RAM | Disk | Network Adapter |
|----|------|-----|------|----------------|
| Kali Linux | 2 cores | 4 GB (4096 MB) | 60 GB (dynamically allocated) | Host-Only + NAT (setup only) |
| Metasploitable2 | 1 core | 512 MB | 8 GB (fixed) | Host-Only |
| Windows 7 | 2 cores | 2 GB (2048 MB) | 40 GB (dynamically allocated) | Host-Only |
| Ubuntu Server | 1 core | 1 GB (1024 MB) | 20 GB (dynamically allocated) | Host-Only |

**Note:** Ensure the host machine has at least:
- 16 GB RAM (32 GB recommended)
- 150 GB free disk space
- CPU with virtualization support (Intel VT-x / AMD-V) enabled in BIOS

---

## 4. Hypervisor Installation

### 4.1 VirtualBox Installation (Windows Host)

1. Download VirtualBox from https://www.virtualbox.org/
2. Run installer `VirtualBox-7.x.x-xxxxx-Win.exe`
3. Select installation directory (default: `C:\Program Files\Oracle\VirtualBox`)
4. **Important:** During installation, ensure the following features are selected:
   - USB Support
   - Networking (Host-Only Network)
   - Python Support (for scripting)
5. After installation, launch VirtualBox
6. **Verify Host-Only Adapter:**
   - Open **File → Host Network Manager**
   - You should see `VirtualBox Host-Only Ethernet Adapter`
   - Check the adapter's IP: should be `192.168.56.1` with netmask `255.255.255.0`
   - If not present, create a new host-only network:
     - Click **Create**
     - Configure IPv4: `192.168.56.1/24`
     - Disable DHCP server

### 4.2 VMware Workstation Installation (Windows Host)

1. Download VMware Workstation Pro from https://www.vmware.com/
2. Run installer and follow the wizard
3. After installation, open **Edit → Virtual Network Editor**
4. Add a **Host-Only** network (e.g., VMnet2):
   - Subnet IP: `192.168.56.0`
   - Subnet mask: `255.255.255.0`
   - **Uncheck** "Use local DHCP service"
5. Apply and close

---

## 5. VM Installation Steps

### 5.1 Kali Linux (Attacker Machine)

#### Download
- ISO: https://www.kali.org/get-kali/#kali-installer-images
- **Recommended:** `kali-linux-2024.x-installer-amd64.iso`

#### VM Creation (VirtualBox)
```
Name: Kali Linux
Type: Linux
Version: Debian (64-bit)
Memory: 4096 MB
CPU: 2 cores
Disk: 60 GB (dynamically allocated)
Network Adapter 1: Host-Only Adapter (vboxnet0)
Network Adapter 2: NAT (for initial package updates, then disable)
```

#### Installation Steps
1. Boot from ISO
2. Select **Graphical Install** or **Install**
3. Language: English → Location: your choice → Keyboard: your layout
4. Hostname: `kali-vapt`
5. Domain: (leave blank)
6. Root password: `kaliVAPT!2024` (change on first boot)
7. Full name: `VAPT Operator`
8. Username: `vapt`
9. Password: `vapt@lab2024`
10. Partitioning: **Guided - Use Entire Disk**
11. Software selection: check **KDE Plasma** (or Xfce for lighter resource usage)
12. Install GRUB to master boot record
13. Reboot

#### Post-Installation Configuration

```bash
# Update system
sudo apt update && sudo apt full-upgrade -y

# Install required tools
sudo apt install -y nmap metasploit-framework wireshark tshark \
    openvas-smb p7zip-full python3-pip python3-venv git curl wget

# Add user to wireshark group (non-root packet capture)
sudo usermod -aG wireshark vapt

# Create scan output directory
mkdir -p ~/vapt-scans

# Disable NAT adapter (keep only Host-Only)
# In VirtualBox settings → Network → Adapter 2 → Uncheck "Enable Network Adapter"

# Verify host-only connectivity
ip a show eth0
# Expected: 192.168.56.10/24

# Restart to apply changes
sudo reboot
```

#### Static IP Configuration

Edit `/etc/network/interfaces.d/eth0` or configure via NetworkManager:

```bash
# For NetworkManager (KDE/GNOME)
nmcli con mod "Wired connection 1" ipv4.addresses 192.168.56.10/24
nmcli con mod "Wired connection 1" ipv4.gateway 192.168.56.1
nmcli con mod "Wired connection 1" ipv4.method manual
nmcli con down "Wired connection 1"
nmcli con up "Wired connection 1"
```

#### Verify Installation
```bash
uname -a
nmap --version
msfconsole --version
tshark --version
```

---

### 5.2 Metasploitable2 (Target 1)

#### Download
- VM Image: https://sourceforge.net/projects/metasploitable/
- File: `Metasploitable2.zip` (~800 MB)
- Extract password: `metasploitable`

#### VM Import (VirtualBox)
```
Extract the ZIP → You get Metasploitable2.vmdk (disk) and other files.

Name: Metasploitable2
Type: Linux
Version: Ubuntu (64-bit)
Memory: 512 MB
CPU: 1 core
Disk: Use existing VMDK (8 GB)
Network Adapter: Host-Only Adapter (vboxnet0)

Note: Do NOT enable NAT on this VM. It must remain fully isolated.
```

#### Boot and Configure
1. Start the VM
2. Default credentials:
   - Username: `msfadmin`
   - Password: `msfadmin`
3. Check IP address:
   ```bash
   ifconfig eth0
   # If no IP assigned, configure static:
   sudo nano /etc/network/interfaces
   ```
4. Set static IP in `/etc/network/interfaces`:
   ```
   auto eth0
   iface eth0 inet static
       address 192.168.56.20
       netmask 255.255.255.0
       gateway 192.168.56.1
   ```
5. Restart networking:
   ```bash
   sudo /etc/init.d/networking restart
   ```
6. Verify:
   ```bash
   ifconfig eth0 | grep inet
   # Should show: 192.168.56.20
   ```

#### Running Services (Pre-installed)
| Port | Service | Version |
|------|---------|---------|
| 21 | vsftpd | 2.3.4 |
| 22 | OpenSSH | 4.7p1 |
| 23 | telnet | |
| 25 | Sendmail | |
| 53 | DNS | ISC BIND 9 |
| 80 | Apache httpd | 2.2.8 |
| 110 | POP3 | |
| 111 | RPC | |
| 139 | Samba smbd | 3.x |
| 443 | Apache https | |
| 445 | Samba smbd | 3.x |
| 3306 | MySQL | |
| 5432 | PostgreSQL | |
| 6667 | UnrealIRCd | |
| 8009 | Apache Tomcat | |
| 8180 | Apache Tomcat | |

---

### 5.3 Windows 7 (Target 2)

#### Download
- ISO: Requires a licensed Windows 7 ISO
- **Alternative:** Use Windows 7 Virtual Machine from Microsoft Edge Dev Tools (free):
  - https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/
  - Download "IE11 on Win7" (expires after 90 days — reset as needed)

#### VM Creation (VirtualBox)
```
Name: Windows 7
Type: Microsoft Windows
Version: Windows 7 (64-bit)
Memory: 2048 MB
CPU: 2 cores
Disk: 40 GB (dynamically allocated)
Network Adapter: Host-Only Adapter (vboxnet0)
```

#### Installation Steps
1. Boot from Windows 7 ISO
2. Select **Custom (Advanced)** installation
3. Create partition on unallocated space → Next
4. Set username: `VAPT User`
5. Set computer name: `WIN7-TARGET`
6. Set password: `Password123!`
7. Select **Work network** when prompted

#### Post-Installation Configuration
```powershell
# Disable Windows Firewall (for lab purposes)
netsh advfirewall set allprofiles state off

# Disable Windows Update
sc config wuauserv start= disabled
sc stop wuauserv

# Enable Remote Desktop
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

# Enable SMB v1 (for exploitation demo)
dism /online /Enable-Feature /FeatureName:SMB1Protocol

# Create a vulnerable user account
net user admin Password123! /add
net localgroup Administrators admin /add

# Disable UAC
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f

# Set static IP
# Control Panel → Network and Sharing Center → Change adapter settings
# IPv4: 192.168.56.30 / 255.255.255.0 / Gateway: 192.168.56.1
```

#### Static IP Configuration (PowerShell)
```powershell
New-NetIPAddress -InterfaceIndex $(Get-NetAdapter).ifIndex `
    -IPAddress 192.168.56.30 `
    -PrefixLength 24 `
    -DefaultGateway 192.168.56.1
```

---

### 5.4 Ubuntu Server (Target 3 — Optional)

#### Download
- ISO: https://ubuntu.com/download/server
- File: `ubuntu-24.04-live-server-amd64.iso`

#### VM Creation (VirtualBox)
```
Name: Ubuntu Server
Type: Linux
Version: Ubuntu (64-bit)
Memory: 1024 MB
CPU: 1 core
Disk: 20 GB (dynamically allocated)
Network Adapter: Host-Only Adapter (vboxnet0)
```

#### Installation Steps
1. Boot from ISO
2. Select language: English
3. Keyboard layout: your choice
4. Network configuration: manual → set static IP `192.168.56.40/24`, gateway `192.168.56.1`
5. Proxy: leave blank
6. Ubuntu archive mirror: default
7. Storage: **Use Entire Disk** → Set LVM group password (optional)
8. Profile setup:
   - Name: `VAPT Operator`
   - Server name: `ubuntu-target`
   - Username: `vaptadmin`
   - Password: `vapt@lab2024`
9. SSH Setup: **Check** "Install OpenSSH server"
10. Featured snaps: skip
11. Reboot

#### Post-Installation
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install additional services for assessment
sudo apt install -y vsftpd apache2 mysql-server php \
    openssh-server netcat-traditional telnetd

# Create vulnerable user
sudo useradd -m -s /bin/bash vulnerable
echo 'vulnerable:vulnpass123' | sudo chpasswd
sudo usermod -aG sudo vulnerable

# Enable vsftpd
sudo systemctl enable vsftpd
sudo systemctl start vsftpd

# Verify IP
ip a show | grep 192.168.56
```

---

## 6. Network Connectivity Verification

### 6.1 Verification Matrix

Execute all tests from **Kali Linux**:

| Test | Command | Expected Result |
|------|---------|----------------|
| Host-only adapter IP | `ip a` | `192.168.56.10/24` |
| Ping host machine | `ping -c 3 192.168.56.1` | 0% packet loss |
| Ping Metasploitable2 | `ping -c 3 192.168.56.20` | 0% packet loss |
| Ping Windows 7 | `ping -c 3 192.168.56.30` | 0% packet loss |
| Ping Ubuntu Server | `ping -c 3 192.168.56.40` | 0% packet loss (if deployed) |
| SSH to Metasploitable2 | `ssh msfadmin@192.168.56.20` | Login successful |
| HTTP to Metasploitable2 | `curl -I http://192.168.56.20` | HTTP/1.1 200 OK |
| SMB to Windows 7 | `smbclient -L //192.168.56.30 -N` | Share listing |
| RDP to Windows 7 | `xfreerdp /v:192.168.56.30` | Connection successful |

### 6.2 Nmap Quick Test
```bash
# Host discovery scan
nmap -sn 192.168.56.0/24

# Should discover:
# 192.168.56.1 (host)
# 192.168.56.10 (self)
# 192.168.56.20 (Metasploitable2)
# 192.168.56.30 (Windows 7)
# (192.168.56.40) (Ubuntu Server - if deployed)
```

---

## 7. Snapshot Strategy

Before starting any assessment, create clean snapshots:

```bash
# VirtualBox CLI snapshots
VBoxManage snapshot "Kali Linux" take "Clean Installation"
VBoxManage snapshot "Metasploitable2" take "Clean Installation"
VBoxManage snapshot "Windows 7" take "Clean Installation"
VBoxManage snapshot "Ubuntu Server" take "Clean Installation"
```

**Restore after each major assessment phase:**
```bash
VBoxManage snapshot "Metasploitable2" restore "Clean Installation"
```

---

## 8. Validation Checklist

### 8.1 Hypervisor
- [ ] VirtualBox/VMware installed successfully
- [ ] Host-Only network adapter created
- [ ] DHCP server disabled on host-only network
- [ ] Host-Only adapter IP: 192.168.56.1/24

### 8.2 Kali Linux
- [ ] Kali Linux installed and booting
- [ ] Static IP: 192.168.56.10/24 configured
- [ ] Root password set and documented
- [ ] VAPT user created with documented password
- [ ] Nmap installed and functional (`nmap --version`)
- [ ] Metasploit installed (`msfconsole --version`)
- [ ] TShark installed (`tshark --version`)
- [ ] Python3 + pip installed
- [ ] Git installed

### 8.3 Metasploitable2
- [ ] VM imported and booting
- [ ] Static IP: 192.168.56.20/24 configured
- [ ] Default credentials working (msfadmin/msfadmin)
- [ ] Web server accessible on port 80
- [ ] SSH accessible on port 22
- [ ] SMB accessible on port 445

### 8.4 Windows 7
- [ ] Windows 7 installed and booting
- [ ] Static IP: 192.168.56.30/24 configured
- [ ] Firewall disabled
- [ ] RDP enabled
- [ ] SMB v1 enabled
- [ ] Admin user created (admin/Password123!)
- [ ] UAC disabled

### 8.5 Ubuntu Server (Optional)
- [ ] Ubuntu Server installed and booting
- [ ] Static IP: 192.168.56.40/24 configured
- [ ] SSH enabled
- [ ] Apache/MySQL running
- [ ] Vulnerable user created

### 8.6 Network Connectivity
- [ ] Kali can ping host machine (192.168.56.1)
- [ ] Kali can ping Metasploitable2 (192.168.56.20)
- [ ] Kali can ping Windows 7 (192.168.56.30)
- [ ] Kali can SSH to Metasploitable2
- [ ] Kali can access Metasploitable2 web server (HTTP 200)
- [ ] Nmap host discovery shows all VMs alive

---

## 9. Screenshots Required

Capture and save to `screenshots/phase-1-lab-setup/`:

1. `01-hypervisor-host-only-network.png` — Host Network Manager showing vboxnet0 with 192.168.56.1/24
2. `02-kali-linux-desktop.png` — Kali Linux desktop with terminal showing `ip a`
3. `03-kali-static-ip.png` — Kali terminal showing 192.168.56.10
4. `04-metasploitable2-login.png` — Metasploitable2 console showing login + ifconfig
5. `05-windows7-desktop.png` — Windows 7 desktop with cmd showing ipconfig
6. `06-windows7-firewall-off.png` — Windows Firewall disabled state
7. `07-ubuntu-server-login.png` — Ubuntu Server terminal showing SSH login
8. `08-ping-test-kali-to-ms2.png` — Ping from Kali to 192.168.56.20 (success)
9. `09-ssh-to-metasploitable2.png` — SSH session from Kali to Metasploitable2
10. `10-nmap-host-discovery.png` — Nmap ping sweep showing all targets
11. `11-virtualbox-vm-list.png` — VirtualBox main window showing all 4 VMs
12. `12-all-vms-snapshots.png` — Snapshot Manager showing clean snapshots

---

## 10. Troubleshooting Guide

### Issue: VMs cannot ping each other

| Cause | Solution |
|-------|----------|
| Host-Only adapter not created | Open VirtualBox → File → Host Network Manager → Create vboxnet0 |
| DHCP enabled | Disable DHCP in Host Network Manager |
| Wrong subnet | Ensure all VMs are on 192.168.56.0/24 |
| Firewall blocking ICMP | Disable Windows Firewall on Win7 |
| VM has only NAT adapter | Change VM network to Host-Only Adapter |
| VMWare: wrong VMnet | In VNware, ensure all VMs use the same VMnet (host-only) |

### Issue: Kali Linux cannot access VMs via SSH/HTTP

| Cause | Solution |
|-------|----------|
| Service not running on target | Start service: `sudo service ssh start` (Metasploitable2) |
| Wrong credentials | Verify with documented credentials |
| Port blocked by firewall | Check Windows 7 firewall is disabled |
| Network profile (Win7) | Set to **Work** or **Private** network |

### Issue: Metasploitable2 not booting

| Cause | Solution |
|-------|----------|
| Corrupted VMDK | Re-extract from ZIP archive |
| Incompatible VirtualBox version | Enable VT-x/AMD-V in BIOS |
| Not enough memory | Ensure at least 512 MB RAM allocated |

### Issue: Windows 7 activation

| Cause | Solution |
|-------|----------|
| Dev VM expired | Download fresh VM from Microsoft or re-arm: `slmgr -rearm` |
| No license | For lab purposes, reinstall or use snapshot restore |

### Issue: NetworkManager clobbers static IP (Kali)

```bash
# Fix: disable NetworkManager for the host-only interface
sudo nmcli device disconnect eth0
# Or configure NetworkManager to use manual IP
```

### Issue: VirtualBox Host-Only adapter missing after Windows update
```bash
# Reinstall VirtualBox Host-Only adapter
# Open VirtualBox → File → Host Network Manager
# Remove and re-create vboxnet0
# Or repair VirtualBox installation
```

---

*End of Lab Setup Guide*
