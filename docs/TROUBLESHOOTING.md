# Troubleshooting Guide

## Phase 1 — Virtual Lab Setup

---

## 1. Hypervisor Issues

### 1.1 Host-Only Adapter Not Created

**Symptom:** No `192.168.56.1` adapter in Host Network Manager or Network Connections

**Solution (VirtualBox):**
```bash
# Open VirtualBox
File → Host Network Manager → Create
# Configure:
IPv4 Address: 192.168.56.1
IPv4 Network Mask: 255.255.255.0
DHCP Server: Unchecked (Disabled)
```

**Solution (VMware):**
```
Edit → Virtual Network Editor
Add Network → VMnet2 (Host-Only)
Subnet IP: 192.168.56.0
Subnet Mask: 255.255.255.0
DHCP: Disabled
```

### 1.2 Host-Only Adapter Missing After Windows Update

**Symptom:** Network adapter disappeared from Device Manager

**Solution:**
```
1. Repair VirtualBox installation:
   Control Panel → Programs → Oracle VM VirtualBox → Repair

2. If that fails, reinstall VirtualBox with network components:
   - Uninstall VirtualBox completely
   - Reboot
   - Reinstall VirtualBox as Administrator
   
3. Or re-add manually from command line (Admin):
   "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" hostonlynet add \
       --name vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0
```

### 1.3 VT-x/AMD-V Not Enabled

**Symptom:** VirtualBox error: "VT-x is not available" or "VERR_VMX_NO_VMX"

**Solution:**
```
1. Reboot host machine
2. Enter BIOS/UEFI (typically F2, F10, F12, or DEL during boot)
3. Find and enable:
   - Intel: "Intel Virtualization Technology" (VT-x)
   - AMD: "SVM Mode"
4. Also enable: "VT-d" if available
5. Save & Exit
6. Verify with: systeminfo | find "Virtualization" (Windows)
```

---

## 2. VM Issues

### 2.1 VM Not Booting

**Symptom:** VM stalls at black screen or shows boot error

**Causes & Solutions:**

| Cause | Check | Fix |
|-------|-------|-----|
| Insufficient memory | Assigned RAM < 512 MB | Increase VM memory |
| Corrupted ISO | Verify SHA256 checksum | Re-download ISO |
| BIOS/EFI mismatch | Guest OS type setting | Set correct OS type in VM settings |
| Disk full | Host disk space | Free up space on host |

### 2.2 Kali Linux Installation Issues

**Symptom:** "No network interfaces detected" during installation

**Solution:**
```
1. During install, ensure network adapter is enabled
2. Use NAT for initial install (switch to host-only after)
3. Try a different network adapter type:
   - VM Settings → Network → Advanced → Adapter Type
   - Try: Intel PRO/1000 MT Desktop (82540EM)
```

### 2.3 Kali Linux Static IP Not Persisting

**Symptom:** IP resets to DHCP after reboot

**Solution:**
```bash
# Method 1: NetworkManager CLI (recommended)
sudo nmcli connection modify "Wired connection 1" \
    ipv4.method manual \
    ipv4.addresses 192.168.56.10/24 \
    ipv4.gateway 192.168.56.1
sudo nmcli connection down "Wired connection 1"
sudo nmcli connection up "Wired connection 1"

# Method 2: Disable NetworkManager for this interface
sudo systemctl stop NetworkManager
sudo systemctl disable NetworkManager
# Then use /etc/network/interfaces
```

### 2.4 Metasploitable2 Not Getting IP

**Symptom:** `ifconfig` shows no IP address on eth0

**Solution:**
```bash
# Log in as msfadmin
sudo nano /etc/network/interfaces
# Ensure it contains:
auto eth0
iface eth0 inet static
    address 192.168.56.20
    netmask 255.255.255.0
    gateway 192.168.56.1

sudo /etc/init.d/networking restart
ifconfig eth0
```

### 2.5 Windows 7 Activation Failed / Expired

**Symptom:** "This copy of Windows is not genuine" — desktop goes black after 1 hour

**Solution:**
```powershell
# Re-arm (extends 30-day trial — usable up to 3 times)
slmgr -rearm
# Reboot

# Or for Edge Dev VMs (90-day expiry):
# Download fresh VM from:
# https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/
```

### 2.6 Windows 7 Network Not Working

**Symptom:** `ipconfig` shows 169.254.x.x (APIPA)

**Solution:**
```powershell
# Check network adapter is set to Host-Only in VM settings
# Then from Windows 7:
ncpa.cpl
# Right-click Local Area Connection → Properties
# Select Internet Protocol Version 4 (TCP/IPv4) → Properties
# Set:
IP address: 192.168.56.30
Subnet mask: 255.255.255.0
Default gateway: 192.168.56.1
```

---

## 3. Network Issues

### 3.1 Pings Fail Between All VMs

**Symptom:** 100% packet loss on all ping tests

**Solution:**
```
1. Check all VMs are on the same Host-Only network
2. Verify vboxnet0 exists and is configured with 192.168.56.1/24
3. Disable DHCP on host-only network
4. Check Windows 7 firewall:
   PowerShell (Admin): netsh advfirewall set allprofiles state off
5. Restart all VMs
```

### 3.2 Ping Works But SSH/HTTP Fails

**Symptom:** Can ping but cannot connect to services

**Solution:**
```
1. Check the service is running on the target:
   Metasploitable2: sudo service ssh status
   Ubuntu: sudo systemctl status ssh

2. Check no host firewall is blocking:
   Windows 7: netsh advfirewall set allprofiles state off
   Ubuntu: sudo ufw disable

3. Try: nmap -sS 192.168.56.20 (check port state)
```

### 3.3 Nmap Shows Zero Hosts

**Symptom:** `nmap -sn 192.168.56.0/24` shows only 192.168.56.1

**Solution:**
```
1. Run sudo nmap (root privileges needed for ping sweep)
2. Check VMs are running (not paused/saved)
3. Manually ping each IP to verify connectivity
4. Try: nmap -sn 192.168.56.20 (test single host)
```

### 3.4 Windows 7 Blocking All Traffic

**Symptom:** Windows 7 unreachable from Kali, but other VMs work

**Solution:**
```powershell
# Run in Windows 7 PowerShell (Admin mode)
netsh advfirewall set allprofiles state off
netsh firewall set opmode disable

# Check network profile is Private/Work:
Get-NetConnectionProfile
# If Public, set to Private:
Set-NetConnectionProfile -InterfaceAlias "Local Area Connection" \
    -NetworkCategory Private

# Restart network adapter:
Restart-NetAdapter -Name "Local Area Connection"
```

---

## 4. Tool-Specific Issues

### 4.1 TShark Permission Denied

**Symptom:** `tshark: There are no interfaces on which a capture can be done`

**Solution:**
```bash
# Add user to wireshark group
sudo usermod -aG wireshark vapt
# Log out and back in
# Verify:
groups
# Should include: vapt wireshark

# Alternatively, run with sudo:
sudo tshark -D
```

### 4.2 Metasploit Database Not Connected

**Symptom:** `msfconsole` starts but shows "Database not connected"

**Solution:**
```bash
# Start and initialize MSF database
sudo systemctl start postgresql
sudo msfdb init
msfconsole
# In msfconsole:
db_status
# Should show: Connected to msf
```

---

## 5. Performance Issues

### 5.1 VMs Running Slowly

**Symptom:** Unresponsive GUI, high host CPU/memory usage

**Solutions:**
```
1. Reduce VM display settings:
   - Disable 3D acceleration
   - Reduce video memory to 32 MB
   - Decrease display resolution

2. VirtualBox: Enable nested paging (VT-x/AMD-V)
   VM Settings → System → Processor → Enable PAE/NX

3. Ensure sufficient host RAM:
   - Close unnecessary host applications
   - Consider running headless (no GUI)

4. Run VMs in headless mode:
   VBoxManage startvm "Kali Linux" --type headless
```

### 5.2 Disk Space Running Out

**Symptom:** "Low disk space" warnings on host

**Solutions:**
```bash
# Compact dynamically allocated VDI/VMDK files
# For VirtualBox VDI:
VBoxManage modifymedium disk "Kali Linux.vdi" --compact

# For VMware VMDK:
# VMware Tools → Shrink Guest

# Clean up:
# Kali: sudo apt autoremove && sudo apt autoclean

# Minimum free space: 20 GB on host
```

---

## 6. Still Having Issues?

If none of the above resolves the problem:

1. **Check virtualization support:**
   - Windows: `systeminfo | find "Virtualization"`
   - Linux: `grep -E "vmx|svm" /proc/cpuinfo`

2. **Check VirtualBox logs:**
   ```
   VirtualBox main window → Right-click VM → Logs → Show Log
   Look for: "Critical" or "Error" entries
   ```

3. **Verify ISO/VM image checksums:**
   ```bash
   # Compare with published SHA256
   certutil -hashfile kali-linux-2024.x-installer-amd64.iso SHA256
   ```

4. **Relevant community resources:**
   - [VirtualBox Forums](https://forums.virtualbox.org/)
   - [Kali Linux Forums](https://forums.kali.org/)
   - [Stack Overflow](https://stackoverflow.com/) (tag: virtualization)

---

*End of Troubleshooting Guide*
