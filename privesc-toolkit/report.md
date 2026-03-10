# Privilege Escalation Assessment Report

**Host:** runsc  
**OS/Arch:** linux/amd64  
**User:** root  
**Date:** 2026-03-10 12:18:31 UTC  
**Duration:** 2m38.438s  

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 14 |
| HIGH | 8 |
| MEDIUM | 6 |
| LOW | 2 |
| INFO | 4 |
| **Total** | **34** |

## SUID/SGID Binary Analysis

### [CRITICAL] T1548.001 - Dangerous SUID binary found: /usr/bin/mount

**Evidence:** mount can be abused to mount attacker-controlled filesystems  
**Remediation:** Remove SUID bit: chmod u-s /usr/bin/mount (if not required)  
**Risk Score:** 95/100  

### [INFO] T1548.001 - Total: 11 SUID binaries, 4 SGID binaries found on system

**Evidence:** Full enumeration complete  
**Risk Score:** 10/100  

## Kernel & Exploit Vector Analysis

### [INFO] T1068 - Kernel version: 4.4.0 | Architecture: amd64

**Evidence:** Baseline information for kernel vulnerability assessment  
**Risk Score:** 10/100  

### [CRITICAL] T1068 - [CVE-2022-0847] DirtyPipe - Overwrite data in arbitrary read-only files, leading to privilege escalation

**Evidence:** Affected versions: 5.8 to 5.16.10 | Current: 4.4.0 | VERIFY MANUALLY  
**Remediation:** Update kernel to latest patched version. Check: https://nvd.nist.gov/vuln/detail/CVE-2022-0847  
**Risk Score:** 95/100  

### [CRITICAL] T1068 - [CVE-2021-4034] PwnKit - pkexec local privilege escalation via crafted environment

**Evidence:** Affected versions: all to all | Current: 4.4.0 | VERIFY MANUALLY  
**Remediation:** Update kernel to latest patched version. Check: https://nvd.nist.gov/vuln/detail/CVE-2021-4034  
**Risk Score:** 95/100  

### [CRITICAL] T1068 - [CVE-2021-3493] OverlayFS PrivEsc - Unprivileged user namespace overlayfs escalation (Ubuntu)

**Evidence:** Affected versions: 4.0 to 5.11 | Current: 4.4.0 | VERIFY MANUALLY  
**Remediation:** Update kernel to latest patched version. Check: https://nvd.nist.gov/vuln/detail/CVE-2021-3493  
**Risk Score:** 95/100  

### [HIGH] T1068 - [CVE-2022-2588] RouteAdvt - Use-after-free in route4 filter leading to privilege escalation

**Evidence:** Affected versions: 4.0 to 5.19 | Current: 4.4.0 | VERIFY MANUALLY  
**Remediation:** Update kernel to latest patched version. Check: https://nvd.nist.gov/vuln/detail/CVE-2022-2588  
**Risk Score:** 75/100  

### [CRITICAL] T1068 - [CVE-2022-34918] Netfilter nft_set - Heap buffer overflow in nf_tables leading to privilege escalation

**Evidence:** Affected versions: 5.8 to 5.18.9 | Current: 4.4.0 | VERIFY MANUALLY  
**Remediation:** Update kernel to latest patched version. Check: https://nvd.nist.gov/vuln/detail/CVE-2022-34918  
**Risk Score:** 95/100  

### [CRITICAL] T1068 - [CVE-2022-0185] FSContext Heap Overflow - Integer underflow in fs_context.c leading to heap overflow

**Evidence:** Affected versions: 5.1 to 5.16.1 | Current: 4.4.0 | VERIFY MANUALLY  
**Remediation:** Update kernel to latest patched version. Check: https://nvd.nist.gov/vuln/detail/CVE-2022-0185  
**Risk Score:** 95/100  

### [HIGH] T1068 - [CVE-2023-0386] OverlayFS Copy-Up - UID/GID mapping bypass in overlayfs copy-up

**Evidence:** Affected versions: 5.11 to 6.2 | Current: 4.4.0 | VERIFY MANUALLY  
**Remediation:** Update kernel to latest patched version. Check: https://nvd.nist.gov/vuln/detail/CVE-2023-0386  
**Risk Score:** 75/100  

### [CRITICAL] T1068 - [CVE-2023-32233] Netfilter nf_tables - Use-after-free in nf_tables batch processing

**Evidence:** Affected versions: 5.0 to 6.3.1 | Current: 4.4.0 | VERIFY MANUALLY  
**Remediation:** Update kernel to latest patched version. Check: https://nvd.nist.gov/vuln/detail/CVE-2023-32233  
**Risk Score:** 95/100  

### [HIGH] T1068 - [CVE-2023-2640] GameOver(lay) - OverlayFS privilege escalation (Ubuntu specific)

**Evidence:** Affected versions: 5.15 to 6.2 | Current: 4.4.0 | VERIFY MANUALLY  
**Remediation:** Update kernel to latest patched version. Check: https://nvd.nist.gov/vuln/detail/CVE-2023-2640  
**Risk Score:** 75/100  

### [HIGH] T1068 - [CVE-2023-3269] StackRot - Use-after-free in maple tree VMA management

**Evidence:** Affected versions: 6.1 to 6.4.1 | Current: 4.4.0 | VERIFY MANUALLY  
**Remediation:** Update kernel to latest patched version. Check: https://nvd.nist.gov/vuln/detail/CVE-2023-3269  
**Risk Score:** 75/100  

### [CRITICAL] T1068 - [CVE-2023-4911] Looney Tunables - glibc ld.so buffer overflow via GLIBC_TUNABLES

**Evidence:** Affected versions: all to all | Current: 4.4.0 | VERIFY MANUALLY  
**Remediation:** Update kernel to latest patched version. Check: https://nvd.nist.gov/vuln/detail/CVE-2023-4911  
**Risk Score:** 95/100  

### [CRITICAL] T1068 - [CVE-2024-1086] nf_tables Use-After-Free - Privilege escalation via nf_tables verdict handling

**Evidence:** Affected versions: 5.14 to 6.7.1 | Current: 4.4.0 | VERIFY MANUALLY  
**Remediation:** Update kernel to latest patched version. Check: https://nvd.nist.gov/vuln/detail/CVE-2024-1086  
**Risk Score:** 95/100  

### [MEDIUM] T1068 - Compilation tools available on system

**Evidence:** Found: /usr/bin/gcc, /usr/bin/cc, /usr/bin/g++, /usr/bin/make, /usr/bin/as, /usr/bin/ld  
**Remediation:** Remove compilers from production systems to impede exploit compilation  
**Risk Score:** 40/100  

## Scheduled Task & Cron Analysis

### [MEDIUM] T1053.003 - No cron access control files found

**Evidence:** Neither /etc/cron.allow nor /etc/cron.deny exists - all users can schedule cron jobs  
**Remediation:** Create /etc/cron.allow with authorized users only  
**Risk Score:** 50/100  

## System Service & Daemon Analysis

### [CRITICAL] T1543.002 - World-writable systemd service: /usr/lib/systemd/system/cryptdisks-early.service

**Evidence:** Permissions: Dcrw-rw-rw-  
**Remediation:** chmod 0644 /usr/lib/systemd/system/cryptdisks-early.service  
**Risk Score:** 90/100  

### [CRITICAL] T1543.002 - World-writable systemd service: /usr/lib/systemd/system/cryptdisks.service

**Evidence:** Permissions: Dcrw-rw-rw-  
**Remediation:** chmod 0644 /usr/lib/systemd/system/cryptdisks.service  
**Risk Score:** 90/100  

### [MEDIUM] T1543.002 - Service explicitly runs as root: e2scrub@.service

**Evidence:** User=root  
**Remediation:** Consider running the service with a dedicated non-root user  
**Risk Score:** 40/100  

### [MEDIUM] T1543.002 - Service explicitly runs as root: e2scrub_reap.service

**Evidence:** User=root  
**Remediation:** Consider running the service with a dedicated non-root user  
**Risk Score:** 40/100  

### [CRITICAL] T1543.002 - World-writable systemd service: /usr/lib/systemd/system/hwclock.service

**Evidence:** Permissions: Dcrw-rw-rw-  
**Remediation:** chmod 0644 /usr/lib/systemd/system/hwclock.service  
**Risk Score:** 90/100  

### [MEDIUM] T1543.002 - Service explicitly runs as root: packagekit.service

**Evidence:** User=root  
**Remediation:** Consider running the service with a dedicated non-root user  
**Risk Score:** 40/100  

### [CRITICAL] T1543.002 - World-writable systemd service: /usr/lib/systemd/system/x11-common.service

**Evidence:** Permissions: Dcrw-rw-rw-  
**Remediation:** chmod 0644 /usr/lib/systemd/system/x11-common.service  
**Risk Score:** 90/100  

## Container Escape & Environment Analysis

### [HIGH] T1611 - User is member of privileged group: root

**Evidence:** Root group membership may grant additional privileges  
**Remediation:** Remove user from root group if not required: gpasswd -d $USER root  
**Risk Score:** 75/100  

### [CRITICAL] T1611 - Writable sensitive proc file: /proc/sysrq-trigger

**Evidence:** Can potentially be used for container escape  
**Remediation:** Use read-only /proc mount or restrict access with AppArmor/SELinux  
**Risk Score:** 85/100  

## Account & Credential Analysis

### [INFO] T1078 - Current user: root (UID: 0, GID: 0)

**Evidence:** uid=0(root) gid=0(root) groups=0(root)  
**Risk Score:** 10/100  

### [INFO] T1078 - Already running as root (UID 0)

**Evidence:** No privilege escalation needed - already at maximum privilege level  
**Risk Score:** 10/100  

### [HIGH] T1078.003 - Current user can read /etc/shadow

**Evidence:** Permissions: -rw-r----- | Password hashes are exposed  
**Remediation:** chmod 0640 /etc/shadow; chown root:shadow /etc/shadow  
**Risk Score:** 90/100  

### [HIGH] T1078.003 - Weak or legacy password hash for user: systemd-network

**Evidence:** Password may use DES or other weak hashing algorithm  
**Remediation:** Force password change for systemd-network with a modern algorithm  
**Risk Score:** 70/100  

### [HIGH] T1078.003 - Weak or legacy password hash for user: polkitd

**Evidence:** Password may use DES or other weak hashing algorithm  
**Remediation:** Force password change for polkitd with a modern algorithm  
**Risk Score:** 70/100  

### [MEDIUM] T1078 - Readable sensitive file: /etc/fstab

**Evidence:** Filesystem table (may contain credentials for CIFS/NFS mounts)  
**Remediation:** Restrict access to /etc/fstab  
**Risk Score:** 50/100  

### [LOW] T1078.003 - World/group-readable home directory: /home/claude

**Evidence:** Permissions: drwxr-xr-x  
**Remediation:** chmod 0750 /home/claude  
**Risk Score:** 30/100  

### [LOW] T1078.003 - World/group-readable home directory: /home/ubuntu

**Evidence:** Permissions: drwxr-x---  
**Remediation:** chmod 0750 /home/ubuntu  
**Risk Score:** 30/100  

