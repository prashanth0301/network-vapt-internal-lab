# Lab Credentials Documentation

## ⚠️ IMPORTANT — Isolated Lab Only
These credentials are for the **isolated virtual lab environment only**.  
All passwords are intentionally simple for educational demonstration.  
**Never use these credentials in production environments.**

---

## 1. Kali Linux (Attacker — 192.168.56.10)

| Account | Username | Password | Description |
|---------|----------|----------|-------------|
| Root | `root` | `kaliVAPT!2024` | Superuser (set during installation) |
| Standard | `vapt` | `vapt@lab2024` | Primary operator account |

---

## 2. Metasploitable2 (Target — 192.168.56.20)

| Account | Username | Password | Description |
|---------|----------|----------|-------------|
| Default | `msfadmin` | `msfadmin` | Root-level access via sudo |
| Service | `user` | `user` | Low-privilege service account |
| Service | `postgres` | `postgres` | PostgreSQL service account |
| FTP Anonymous | `anonymous` | (any email) | vsftpd 2.3.4 backdoor |

---

## 3. Windows 7 (Target — 192.168.56.30)

| Account | Username | Password | Description |
|---------|----------|----------|-------------|
| Administrator | `Administrator` | `Password123!` | Built-in admin (may need enabling) |
| Custom Admin | `admin` | `Password123!` | Created for exploitation demos |
| Standard User | `VAPT User` | `Password123!` | Default installation user |

**Note:** Windows 7 is intentionally left unpatched with:
- Firewall disabled
- UAC disabled
- SMB v1 enabled
- RDP enabled

---

## 4. Ubuntu Server (Optional Target — 192.168.56.40)

| Account | Username | Password | Description |
|---------|----------|----------|-------------|
| Sudo User | `vaptadmin` | `vapt@lab2024` | Administrative account |
| Vulnerable | `vulnerable` | `vulnpass123` | Low-privilege test account |

---

## 5. Service Credentials

| Service | Location | Username | Password |
|---------|----------|----------|----------|
| MySQL (Metasploitable2) | 192.168.56.20:3306 | `root` | (blank) |
| PostgreSQL (Metasploitable2) | 192.168.56.20:5432 | `postgres` | `postgres` |
| MySQL (Ubuntu Server) | 192.168.56.40:3306 | `root` | `vapt@lab2024` |

---

## 6. Snapshot Restore Note

After exploitation phases, restore VMs to clean snapshot:
```bash
VBoxManage snapshot "VM-NAME" restore "Clean Installation"
```

This resets all credentials back to the values documented above.
