# CyberPatriot hardening scripts

Two scripts with the same layout: `harden.ps1` for Windows 10/11/Server, `harden.sh` for Ubuntu/Debian/Mint.
Both are menu-driven, show what they found, and ask before every change.

## Every image, in this order

1. Read the image README. Note authorized users, admins, and required services/software.
2. Copy this folder onto the image.
3. **Answer the forensics questions** (the forensics helper below gathers the evidence). Nothing here deletes files, but removing a user or program can erase the answer.
4. Paste the README into the tool (below). It fills in the authorized users, administrators and required services.
5. **Check what it found against the README.** The reader is a best guess from the text.
6. Run an audit first, then the real thing.

## Windows

Double-click `run-windows.bat`. It opens the window as Administrator:

1. Paste the README text into the left box and click **Read README**.
2. Fix the administrators / standard users / required services boxes if anything is wrong.
3. Tick the sections you want and click **Run**. "Audit only" starts ticked, so the first run only reports.

Each change asks in a Yes/No box. Cancel answers No to everything left in that run.

For the text-menu version, double-click `run-windows-console.bat` (menu option `R` opens Notepad for the README), or from an admin PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\harden.ps1 -AuditOnly
```

## Linux

Text menu only (no window). Menu option `R` lets you paste the README into the terminal, or save it to a file and pass it in:

```bash
sudo bash harden.sh --audit --readme readme.txt
```

```bash
sudo bash harden.sh
```

## Forensics questions

Windows: the **Forensics...** button in the window (or `F` in the text menu). Linux: `F` in the menu.

Every forensics question is different, so the helper cannot answer them for you. It does the legwork:

- Finds the question files on every Desktop and shows them.
- Looks up what the question names: files and folders (owner, dates, MD5/SHA1/SHA256, hidden data streams on Windows), users (SID or UID, groups, last logon), and anything that looks encoded (Base64, hex, binary).
- Lists ports, shares, groups or scheduled tasks when the question mentions them.
- Tools for the rest: file info + hashes, decode text (also ROT13 and reversed), find a file by name, user info.
- Writes your answer onto the `ANSWER:` line. The untouched original is kept in `logs/`.

You read the question, decide the answer, and check the file afterwards. Answer formats are strict, so follow the example in the question exactly.

## How the README is used

The pasted text is turned into three files that every section reads. You can also edit them by hand.

| File | Comes from | Used for |
|------|-----------|----------|
| `admins.txt` | "Authorized Administrators" list | Who may be in Administrators / sudo |
| `users.txt` | "Authorized Users" list | Everyone else allowed to exist |
| `services.txt` | "Critical Services" list | Services that are kept instead of offered for removal |

`services.txt` holds one tag per line: `rdp ssh ftp web smb dns mail sql print telnet snmp vnc`.
A required service is skipped by the services/packages sections, and on Linux its port is opened in the firewall.
A critical service the reader does not recognize is printed as a warning; protect that one yourself.
The Windows report also marks any suspicious program whose name appears in the README.

## Options

| Windows      | Linux     | Effect |
|--------------|-----------|--------|
| `-AuditOnly` | `--audit` | Report problems, change nothing |
| `-Yes`       | `--yes`   | Auto-accept safe changes; users, services, packages, RDP/SSH still ask |
| `-All`       | `--all`   | Run every section in order, no menu |

## What it covers

| Area | Windows | Linux |
|------|---------|-------|
| Users | Unauthorized users, Administrators group, Guest/Administrator, password flags, bulk password reset | Unauthorized users, sudo group, UID 0, empty passwords, root lock, bulk password reset |
| Passwords | Length, age, history, complexity, lockout | login.defs aging, pwquality, history, nullok, faillock lockout |
| Network | Firewall on for all profiles, RDP, SMBv1 | ufw, SSH hardening, sysctl |
| System | Audit policy, UAC and other security options, services, features, Defender, auto-update policy | Unwanted packages, automatic updates, file permissions, guest login, auditd |
| Report | Media files, suspicious programs, shares, scheduled tasks, startup items, ports, hosts file | Media files, cron, sudoers, SUID files, authorized_keys, ports, hosts file |

Logs and the report go to `logs/`. The Linux script copies every file it edits to `backups/<timestamp>/` first.

## Not covered (do by hand)

- Deciding the forensics answers (the helper only gathers evidence)
- Deleting media and uninstalling programs (the report lists them; you decide)
- Installing updates on Windows; updating browsers and README-required software
- Hardening required services in their own config files (IIS, Apache, vsftpd, Samba, MySQL)
- Windows User Rights Assignment

## Before competition day

- Practice with these on the practice images and adjust them to what the scoring engine rewards.
- Check the current CyberPatriot rules with your coach on scripts and outside/AI help, and make sure your team understands every line it runs.
