#!/usr/bin/env bash
#
# CyberPatriot Linux hardening helper (Ubuntu / Debian / Mint).
#
# Menu-driven. Every change is shown and confirmed before it is made, and
# every file it edits is copied to ./backups/<timestamp>/ first.
# Fill in users.txt and admins.txt (from the image README) before running.
#
# DO THE FORENSICS QUESTIONS FIRST. This script never deletes files, but
# removing users/packages can destroy the evidence a question asks about.
#
# Usage:  sudo bash harden.sh [--audit] [--yes] [--all]
#   --audit  report what is wrong, change nothing
#   --yes    auto-accept the safe changes; users, packages, SSH and PAM
#            lockout still ask
#   --all    run every section in order instead of showing the menu
#   --readme FILE  read the image README from FILE and fill in users.txt,
#            admins.txt and services.txt from it (menu option R pastes it)

set -u

AUDIT=0; YES=0; ALL=0; README_FILE=''
while [[ $# -gt 0 ]]; do
    case "$1" in
        --audit)  AUDIT=1 ;;
        --yes)    YES=1 ;;
        --all)    ALL=1 ;;
        --readme) README_FILE="${2:-}"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

if [[ $EUID -ne 0 ]]; then
    echo "Run this with sudo:  sudo bash $0"
    exit 1
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOGDIR="$DIR/logs"
BACKUPDIR="$DIR/backups/$STAMP"
REPORT="$LOGDIR/report-linux-$STAMP.txt"
mkdir -p "$LOGDIR"
exec > >(tee -a "$LOGDIR/harden-linux-$STAMP.log") 2>&1

ME="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
HAVE_APT=0; command -v apt-get >/dev/null 2>&1 && HAVE_APT=1
export DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------- helpers ---

section() { printf '\n\033[36m=== %s ===\033[0m\n' "$1"; }
info()    { printf '    %s\n' "$1"; }
good()    { printf '\033[32m[ok]\033[0m %s\n' "$1"; }
warn()    { printf '\033[33m[!!]\033[0m %s\n' "$1"; }
bad()     { printf '\033[31m[xx]\033[0m %s\n' "$1"; }

# confirm "question" [risky]  -- risky changes always ask, even with --yes
confirm() {
    local question="$1" risky="${2:-}" answer
    if [[ $AUDIT -eq 1 ]]; then info "(audit only) skipped: $question"; return 1; fi
    if [[ $YES -eq 1 && -z "$risky" ]]; then info "auto-yes: $question"; return 0; fi
    read -r -p "$question [y/N] " answer < /dev/tty
    [[ "$answer" =~ ^([yY]|[yY][eE][sS])$ ]]
}

# Strips comments, blank lines, whitespace and Windows line endings.
read_list() {
    [[ -f "$DIR/$1" ]] || return 0
    tr -d '\r' < "$DIR/$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | grep -v -e '^#' -e '^$'
}

in_list() {
    local needle="$1" item; shift
    for item in "$@"; do [[ "$item" == "$needle" ]] && return 0; done
    return 1
}

backup() {
    [[ -e "$1" ]] || return 0
    mkdir -p "$BACKUPDIR$(dirname "$1")"
    cp -a "$1" "$BACKUPDIR$1"
}

is_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'ok installed'; }

# set_kv FILE KEY VALUE SEPARATOR -- replace an active "KEY ..." line, or append one
set_kv() {
    local file="$1" key="$2" value="$3" sep="$4"
    if grep -Eq "^[[:space:]]*${key}([[:space:]]|=|$)" "$file"; then
        sed -ri "s~^[[:space:]]*${key}([[:space:]]|=|$).*~${key}${sep}${value}~" "$file"
    else
        printf '%s%s%s\n' "$key" "$sep" "$value" >> "$file"
    fi
}

report() {
    local title="$1" body="$2" count=0
    [[ -n "$body" ]] && count=$(printf '%s\n' "$body" | wc -l | tr -d ' ')
    { printf '\n##### %s (%s)\n' "$title" "$count"; printf '%s\n' "${body:-(none)}"; } >> "$REPORT"
    if [[ $count -eq 0 ]]; then
        good "$title - none found"
    else
        warn "$title - $count found:"
        printf '%s\n' "$body" | head -n 15 | sed 's/^/    /'
        [[ $count -gt 15 ]] && info "... $((count - 15)) more in the report file"
    fi
}

human_users() { awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' /etc/passwd; }

# ----------------------------------------------------------------- README ---
#
# The image README is turned into three small files that every section reads:
#   admins.txt    authorized administrators
#   users.txt     authorized standard users
#   services.txt  required services, as tags from SERVICE_TAGS

SERVICE_TAGS='rdp ssh ftp web smb dns mail sql print telnet snmp vnc'

is_required() { read_list services.txt | grep -qx "$1"; }

# Which services.txt tag protects a package (empty = none).
pkg_tag() {
    case "$1" in
        vsftpd|proftpd-basic|pure-ftpd)        echo ftp ;;
        apache2|nginx|lighttpd)                echo web ;;
        samba)                                 echo smb ;;
        bind9)                                 echo dns ;;
        postfix|exim4|dovecot-core)            echo mail ;;
        mysql-server|mariadb-server|postgresql) echo sql ;;
        cups)                                  echo print ;;
        telnetd|inetutils-telnetd)             echo telnet ;;
        snmpd)                                 echo snmp ;;
        tightvncserver|x11vnc)                 echo vnc ;;
        xrdp)                                  echo rdp ;;
    esac
}

# Prints one finding per line:  A:admin  U:user  Y:you  S:service-tag  X:unrecognized service
# It is a best guess - always look over the result before trusting it.
parse_readme() {
    tr -d '\r' < "$1" | awk '
        function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
        function service(item,   l) {
            l = tolower(item)
            if (l == "" ) return
            got = 1
            if (l ~ /^\(?(none|n\/a)\)?\.?$/) return
            if      (l ~ /remote desktop|rdp|terminal services/)      print "S:rdp"
            else if (l ~ /ssh/)                                       print "S:ssh"
            else if (l ~ /ftp|filezilla/)                             print "S:ftp"
            else if (l ~ /iis|apache|nginx|http|web|world wide/)      print "S:web"
            else if (l ~ /samba|smb|file shar|file server/)           print "S:smb"
            else if (l ~ /dns|bind/)                                  print "S:dns"
            else if (l ~ /mail|smtp|postfix|dovecot|exchange|pop3|imap/) print "S:mail"
            else if (l ~ /sql|maria|postgres|database/)               print "S:sql"
            else if (l ~ /print|cups/)                                print "S:print"
            else if (l ~ /telnet/)                                    print "S:telnet"
            else if (l ~ /snmp/)                                      print "S:snmp"
            else if (l ~ /vnc/)                                       print "S:vnc"
            else print "X:" item
        }
        {
            line = trim($0)
            sub(/^[-*]+[ \t]*/, "", line)
            low = tolower(line)

            if (low ~ /^authorized[ \t]+administrators[ \t]*:?$/) { mode = "A"; next }
            if (low ~ /^authorized[ \t]+users[ \t]*:?$/)          { mode = "U"; next }
            if (low ~ /^critical[ \t]+services/) {
                mode = "S"; got = 0
                colon = index(line, ":")
                if (colon) {
                    n = split(substr(line, colon + 1), parts, ",")
                    for (i = 1; i <= n; i++) service(trim(parts[i]))
                    if (got) mode = ""    # the list was on the heading line itself
                }
                next
            }
            if (mode == "A" || mode == "U") {
                if (line == "" || low ~ /^\(?password/) next
                you = 0
                if (low ~ /\(you\)$/) { you = 1; sub(/[ \t]*\([Yy][Oo][Uu]\)$/, "", line) }
                if (line ~ /^[A-Za-z][A-Za-z0-9_.-]*$/) {
                    print mode ":" line
                    if (you) print "Y:" line
                } else {
                    mode = ""
                }
                next
            }
            if (mode == "S") {
                if (line == "") { if (got) mode = ""; next }
                if (length(line) > 60) { mode = ""; next }
                service(line)
            }
        }' | awk '!seen[$0]++'
}

save_list() {
    local file="$DIR/$1" header="$2" item; shift 2
    { echo "# $header"; for item in "$@"; do echo "$item"; done; } > "$file"
    [[ -n "${SUDO_USER:-}" ]] && chown "$SUDO_USER" "$file" 2>/dev/null
    return 0
}

# import_readme [FILE]  -- with no file, you paste the README into the terminal
import_readme() {
    section 'Read the image README'
    local file="${1:-}" out admins users services unmapped you answer item
    if [[ -z "$file" ]]; then
        file="$DIR/readme.txt"
        info 'Paste the README text now. When it is all in, press Enter, then Ctrl-D.'
        cat < /dev/tty > "$file"
    fi
    if [[ ! -s "$file" ]]; then bad "README file is empty or missing: $file"; return; fi

    out=$(parse_readme "$file")
    admins=$(printf '%s\n' "$out"   | sed -n 's/^A://p' | tr '\n' ' ')
    users=$(printf '%s\n' "$out"    | sed -n 's/^U://p' | tr '\n' ' ')
    services=$(printf '%s\n' "$out" | sed -n 's/^S://p' | tr '\n' ' ')
    unmapped=$(printf '%s\n' "$out" | sed -n 's/^X://p')
    you=$(printf '%s\n' "$out"      | sed -n 's/^Y://p' | head -n 1)

    if [[ -z "$admins$users" ]]; then
        bad "Could not find the 'Authorized Administrators' / 'Authorized Users' lists. Edit users.txt and admins.txt by hand."
    else
        good "Administrators: ${admins:-(none)}"
        good "Standard users: ${users:-(none)}"
    fi
    if [[ -n "$services" ]]; then good "Required services: $services"; else info 'Required services: none recognized'; fi
    while IFS= read -r item; do
        [[ -n "$item" ]] && warn "Critical service I do not recognize (protect it yourself): $item"
    done <<< "$unmapped"
    [[ -n "$you" && "$you" != "$ME" ]] && warn "README says you are '$you' but you are running as '$ME'."
    warn 'This is a best guess from the text. Check the lists against the README before running.'

    read -r -p 'Save these to admins.txt / users.txt / services.txt? [y/N] ' answer < /dev/tty
    if [[ "$answer" =~ ^([yY]|[yY][eE][sS])$ ]]; then
        # shellcheck disable=SC2086
        save_list admins.txt 'Authorized ADMINISTRATORS, one per line. Include yourself.' $admins
        # shellcheck disable=SC2086
        save_list users.txt 'Authorized STANDARD users, one per line.' $users
        # shellcheck disable=SC2086
        save_list services.txt "Required services, one tag per line: $SERVICE_TAGS" $services
        good 'Lists saved'
    fi
}

# -------------------------------------------------------------- forensics ---
#
# Every forensics question is different, so this cannot answer them for you.
# It finds the question files, looks up what a question names (files, users,
# encoded text), gives you the common tools, and writes your answer onto the
# ANSWER: line. You still read the question and pick the answer.

is_text() { [[ -n "$1" ]] && ! printf '%s' "$1" | LC_ALL=C grep -q '[^[:print:][:space:]]'; }

file_summary() {
    local path="$1"
    if [[ -z "$path" || ! -e "$path" ]]; then echo "Not found: $path"; return; fi
    stat -c 'Path:     %n
Owner:    %U (uid %u)   Group: %G (gid %g)
Perms:    %A (%a)
Size:     %s bytes
Modified: %y
Changed:  %z' "$path"
    if [[ -f "$path" ]]; then
        echo "Type:     $(file -b "$path" 2>/dev/null)"
        echo "MD5:      $(md5sum    < "$path" | cut -d' ' -f1)"
        echo "SHA1:     $(sha1sum   < "$path" | cut -d' ' -f1)"
        echo "SHA256:   $(sha256sum < "$path" | cut -d' ' -f1)"
    elif [[ -d "$path" ]]; then
        echo 'Contents:'
        ls -la "$path" | head -n 40
    fi
}

user_summary() {
    local name="$1"
    if ! id "$name" >/dev/null 2>&1; then echo "No user named '$name'"; return; fi
    id "$name"
    getent passwd "$name" | awk -F: '{ print "Comment: " $5; print "Home:    " $6; print "Shell:   " $7 }'
    echo "Password: $(passwd -S "$name" 2>/dev/null | awk '{ print $2, "(last changed " $3 ")" }')"
    lastlog -u "$name" 2>/dev/null | tail -n 1 | sed 's/^/Last login: /'
}

# decode_all TEXT [quiet] -- tries the common encodings, prints the readable ones.
# "quiet" leaves out the ones that always produce something (ROT13, reversed).
decode_all() {
    local text="$1" quiet="${2:-}" out hex bits i
    [[ -n "$text" ]] || return 0

    out=$(printf '%s' "$text" | base64 -d 2>/dev/null | tr -d '\0')
    is_text "$out" && echo "Base64  -> $out"

    hex=$(printf '%s' "$text" | sed -e 's/0x//g' -e 's/[[:space:]:,-]//g')
    if [[ ${#hex} -ge 4 && "$hex" =~ ^([0-9A-Fa-f]{2})+$ ]]; then
        out=$(printf '%b' "$(printf '%s' "$hex" | sed 's/../\\x&/g')" | tr -d '\0')
        is_text "$out" && echo "Hex     -> $out"
    fi

    bits=$(printf '%s' "$text" | tr -d '[:space:]')
    if [[ ${#bits} -ge 8 && $(( ${#bits} % 8 )) -eq 0 && "$bits" =~ ^[01]+$ ]]; then
        out=''
        for (( i = 0; i < ${#bits}; i += 8 )); do
            out+=$(printf '%b' "\\x$(printf '%x' "$(( 2#${bits:i:8} ))")")
        done
        is_text "$out" && echo "Binary  -> $out"
    fi

    if [[ -z "$quiet" ]]; then
        echo "ROT13   -> $(printf '%s' "$text" | tr 'A-Za-z' 'N-ZA-Mn-za-m')"
        echo "Reversed-> $(printf '%s' "$text" | rev)"
    fi
    return 0
}

# Looks up everything the question text names.
forensic_clues() {
    local question word token name found=0 decoded seen=' '
    question=$(tr -d '\r' < "$1" | grep -v '^[[:space:]]*ANSWER')

    # --- file and folder paths
    set -f
    for word in $question; do
        token="${word#[\"\'\(]}"
        while [[ "$token" == *[.,\;:\)\?\!\"\'] ]]; do token="${token%?}"; done
        [[ "$token" == /?* || "$token" == \~/* ]] || continue
        token="${token/#\~/$(getent passwd "$ME" | cut -d: -f6)}"
        [[ "$seen" == *" $token "* ]] && continue
        seen+="$token "
        if [[ -e "$token" ]]; then
            echo '--- Named in the question:'
            file_summary "$token"
        else
            echo "--- The question names a path that does not exist (deleted? hidden? typo?): $token"
        fi
        echo; found=1
    done
    set +f

    # --- users mentioned by name (real people and root only; "mail", "games"
    #     and friends are ordinary words too)
    for name in root $(human_users); do
        if printf '%s\n' "$question" | grep -qw -- "$name"; then
            echo '--- User mentioned in the question:'
            user_summary "$name"
            echo; found=1
        fi
    done

    # --- things that look encoded
    while IFS= read -r token; do
        [[ -n "$token" ]] || continue
        decoded=$(decode_all "$token" quiet)
        if [[ -n "$decoded" ]]; then
            echo "--- This looks encoded: $token"
            echo "$decoded"
            echo; found=1
        fi
    done < <(printf '%s\n' "$question" | grep -oE '[A-Za-z0-9+/]{16,}={0,2}|([0-9A-Fa-f]{2}[ :]){7,}[0-9A-Fa-f]{2}|([01]{8} ?){4,}')

    # --- topic hints
    if printf '%s\n' "$question" | grep -qiE '\bports?\b|listening'; then
        echo '--- The question mentions ports. Listening:'
        ss -tulpnH 2>/dev/null | awk '{ print "  " $1, $5, $7 }' | sort -u
        echo; found=1
    fi
    if printf '%s\n' "$question" | grep -qiE '\bgroups?\b'; then
        echo '--- The question mentions groups. Groups that have members:'
        awk -F: '$4 != "" { print "  " $1 " (gid " $3 "): " $4 }' /etc/group
        echo; found=1
    fi
    if printf '%s\n' "$question" | grep -qiE 'cron|scheduled'; then
        echo '--- The question mentions scheduled jobs:'
        ls -1 /var/spool/cron/crontabs 2>/dev/null | sed 's|^|  user crontab: |'
        grep -rEHv '^[[:space:]]*(#|$)' /etc/crontab /etc/cron.d 2>/dev/null | sed 's/^/  /'
        echo; found=1
    fi

    if [[ $found -eq 0 ]]; then
        echo 'Nothing in this question could be looked up automatically.'
        echo 'Read it and use the tools: file info + hashes, decode, find file, user info.'
    fi
}

# write_answers FILE ANSWER...  -- fills the ANSWER: lines in order
write_answers() {
    local file="$1" tmp answers; shift
    [[ -e "$LOGDIR/$(basename "$file").original" ]] || cp -p "$file" "$LOGDIR/$(basename "$file").original"
    tmp=$(mktemp); answers=$(mktemp)
    printf '%s\n' "$@" > "$answers"
    awk -v answers="$answers" '
        BEGIN { while ((getline line < answers) > 0) a[++n] = line }
        /^[ \t]*ANSWER[ \t]*:/ && k < n { print "ANSWER: " a[++k]; next }
        { print }
        END { while (k < n) print "ANSWER: " a[++k] }' "$file" > "$tmp" && cat "$tmp" > "$file"
    rm -f "$tmp" "$answers"
}

do_forensics() {
    section 'Forensics questions'
    local files=() file choice input answers=() part
    while IFS= read -r file; do files+=("$file"); done < <(ls -1 /home/*/Desktop/*[Ff]orensic* /root/Desktop/*[Ff]orensic* 2>/dev/null)
    if [[ ${#files[@]} -eq 0 ]]; then warn 'No files with "forensic" in the name on any Desktop.'; return; fi

    for file in "${files[@]}"; do
        printf '\n\033[36m----- %s\033[0m\n' "$file"
        tr -d '\r' < "$file" | sed 's/^/    /'
        printf '\n\033[36mClues:\033[0m\n'
        forensic_clues "$file" | sed 's/^/    /'

        while true; do
            echo
            read -r -p '[a]nswer  [h]ash/file info  [d]ecode  [f]ind file  [u]ser  [n]ext question  [q]uit: ' choice < /dev/tty
            case "$choice" in
                a|A)
                    read -r -p 'Answer (separate several answers with | ): ' input < /dev/tty
                    answers=()
                    while IFS= read -r part; do
                        part=$(printf '%s' "$part" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
                        [[ -n "$part" ]] && answers+=("$part")
                    done < <(printf '%s\n' "$input" | tr '|' '\n')
                    if [[ ${#answers[@]} -eq 0 ]]; then warn 'Nothing written'; continue; fi
                    write_answers "$file" "${answers[@]}" && good "Wrote ${#answers[@]} answer(s). The file now reads:"
                    tr -d '\r' < "$file" | sed 's/^/    /'
                    ;;
                h|H) read -r -p 'File or folder path: ' input < /dev/tty; file_summary "$input" | sed 's/^/    /' ;;
                d|D) read -r -p 'Text to decode: ' input < /dev/tty; decode_all "$input" | sed 's/^/    /' ;;
                f|F) read -r -p 'File name or part of it: ' input < /dev/tty
                     info 'Searching (can take a minute)...'
                     find / -xdev -iname "*$input*" -not -path '/proc/*' -not -path '/sys/*' -not -path '/snap/*' 2>/dev/null | head -n 100 | sed 's/^/    /' ;;
                u|U) read -r -p 'User name: ' input < /dev/tty; user_summary "$input" | sed 's/^/    /' ;;
                n|N) break ;;
                q|Q) return ;;
                *) warn 'Not an option' ;;
            esac
        done
    done
}

# ------------------------------------------------------------------ users ---

do_users() {
    section 'Users and groups'
    local admins=() users=() name line
    while IFS= read -r line; do admins+=("$line"); done < <(read_list admins.txt)
    while IFS= read -r line; do users+=("$line");  done < <(read_list users.txt)
    users+=("${admins[@]+"${admins[@]}"}")

    if [[ ${#users[@]} -eq 0 ]]; then
        bad 'users.txt and admins.txt are empty. Fill them in from the README, then re-run this section.'
        return
    fi
    if [[ "$ME" != root ]] && ! in_list "$ME" "${users[@]}"; then
        bad "You are '$ME' but that name is not in users.txt/admins.txt."
        bad 'Fix the lists first so this script cannot remove your own account.'
        return
    fi

    # --- unauthorized accounts
    for name in $(human_users); do
        in_list "$name" "${users[@]}" && continue
        warn "Unauthorized user: $name"
        if confirm "  Remove user '$name'? (their home folder is kept)" risky; then
            userdel "$name" && good "Removed $name"
        fi
    done

    # --- listed but missing
    for name in "${users[@]}"; do
        id "$name" >/dev/null 2>&1 || warn "'$name' is in your lists but does not exist. If the README says to add them: adduser $name"
    done

    # --- admin groups
    local group members
    for group in sudo admin wheel; do
        getent group "$group" >/dev/null || continue
        members=$(getent group "$group" | cut -d: -f4 | tr ',' ' ')
        for name in $members; do
            in_list "$name" "${admins[@]+"${admins[@]}"}" && continue
            if [[ "$name" == "$ME" ]]; then warn "You ($ME) are in '$group' but not in admins.txt - leaving you alone."; continue; fi
            warn "Not an authorized administrator: $name (group $group)"
            if confirm "  Remove '$name' from $group?" risky; then
                gpasswd -d "$name" "$group" >/dev/null && good "Demoted $name"
            fi
        done
    done
    if getent group sudo >/dev/null; then
        for name in "${admins[@]+"${admins[@]}"}"; do
            id "$name" >/dev/null 2>&1 || continue
            id -nG "$name" | tr ' ' '\n' | grep -qx sudo && continue
            warn "Authorized administrator is missing from sudo: $name"
            if confirm "  Add '$name' to sudo?" risky; then
                gpasswd -a "$name" sudo >/dev/null && good "Promoted $name"
            fi
        done
    fi

    # --- UID 0 impostors, empty passwords, root login
    local uid0 empty
    uid0=$(awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd)
    [[ -n "$uid0" ]] && bad "Accounts with UID 0 besides root (fix by hand in /etc/passwd): $uid0"

    empty=$(awk -F: '$2 == "" { print $1 }' /etc/shadow)
    for name in $empty; do
        warn "$name has an EMPTY password"
        if confirm "  Lock '$name' until a password is set?"; then passwd -l "$name" >/dev/null && good "Locked $name"; fi
    done

    if passwd -S root 2>/dev/null | awk '{ exit ($2 == "L") ? 0 : 1 }'; then
        good 'root account is locked'
    else
        warn 'root account has a usable password'
        if confirm '  Lock the root account? (sudo keeps working)'; then passwd -l root >/dev/null && good 'Locked root'; fi
    fi

    # --- passwords
    local others=() pw pw2
    for name in $(human_users); do
        [[ "$name" == "$ME" ]] && continue
        in_list "$name" "${users[@]}" && others+=("$name")
    done
    if [[ ${#others[@]} -gt 0 ]] && confirm "Set one new strong password on every user except you ($ME)?" risky; then
        read -r -s -p '  New password (12+ chars, upper/lower/number/symbol): ' pw < /dev/tty; echo
        read -r -s -p '  Again: ' pw2 < /dev/tty; echo
        if [[ -z "$pw" || "$pw" != "$pw2" ]]; then
            bad 'Passwords empty or did not match - nothing changed'
        else
            for name in "${others[@]}"; do
                printf '%s:%s\n' "$name" "$pw" | chpasswd && good "Password set for $name"
            done
            info 'Write that password down. Your own password was not changed.'
        fi
    fi
}

# -------------------------------------------------------- password policy ---

do_password_policy() {
    section 'Password policy'
    grep -E '^[[:space:]]*PASS_(MAX|MIN|WARN)' /etc/login.defs | sed 's/^/    /'

    if confirm 'Set password aging: max 90 days, min 7, warn 14 (login.defs + existing users)?'; then
        backup /etc/login.defs
        set_kv /etc/login.defs PASS_MAX_DAYS 90 $'\t'
        set_kv /etc/login.defs PASS_MIN_DAYS 7  $'\t'
        set_kv /etc/login.defs PASS_WARN_AGE 14 $'\t'
        local name
        for name in $(human_users); do chage -M 90 -m 7 -W 14 "$name"; done
        good 'Password aging set'
    fi

    if [[ -f /etc/pam.d/common-password ]] && confirm 'Require complex passwords (min length 10, all four character classes, remember last 5)?'; then
        if [[ $HAVE_APT -eq 1 ]] && ! is_installed libpam-pwquality; then
            apt-get install -y -q libpam-pwquality >/dev/null || bad 'Could not install libpam-pwquality'
        fi
        if [[ -f /etc/security/pwquality.conf ]]; then
            backup /etc/security/pwquality.conf
            local key
            set_kv /etc/security/pwquality.conf minlen 10 ' = '
            for key in dcredit ucredit lcredit ocredit; do set_kv /etc/security/pwquality.conf "$key" -1 ' = '; done
        fi
        backup /etc/pam.d/common-password
        sed -ri '/pam_unix\.so/{/remember=/!s/$/ remember=5/}' /etc/pam.d/common-password
        good 'Password complexity and history set'
    fi

    if grep -q 'nullok' /etc/pam.d/common-auth 2>/dev/null; then
        warn 'PAM allows empty passwords (nullok)'
        if confirm '  Remove nullok from common-auth?'; then
            backup /etc/pam.d/common-auth
            sed -ri 's/[[:space:]]+nullok(_secure)?//g' /etc/pam.d/common-auth
            good 'nullok removed'
        fi
    fi

    # Account lockout. Uses pam-auth-update profiles (the CIS Ubuntu method)
    # rather than hand-editing the PAM stack.
    if command -v pam-auth-update >/dev/null 2>&1 && find /lib /usr/lib -name pam_faillock.so 2>/dev/null | grep -q .; then
        if grep -q pam_faillock /etc/pam.d/common-auth; then
            good 'Account lockout (pam_faillock) already active'
        else
            warn 'No account lockout configured'
            info 'This edits PAM. Keep a second root terminal open (sudo -i) until you have'
            info 'confirmed in a NEW terminal that sudo still works.'
            if confirm '  Lock accounts for 30 min after 5 failed logins?' risky; then
                backup /etc/pam.d/common-auth
                backup /etc/pam.d/common-account
                backup /etc/security/faillock.conf
                touch /etc/security/faillock.conf
                set_kv /etc/security/faillock.conf deny 5 ' = '
                set_kv /etc/security/faillock.conf unlock_time 1800 ' = '
                cat > /usr/share/pam-configs/faillock <<'EOF'
Name: Enforce failed login attempt counter
Default: no
Priority: 0
Auth-Type: Primary
Auth:
	[default=die] pam_faillock.so authfail
	sufficient pam_faillock.so authsucc
EOF
                cat > /usr/share/pam-configs/faillock_notify <<'EOF'
Name: Notify on failed login attempts
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
	requisite pam_faillock.so preauth
EOF
                pam-auth-update --enable faillock faillock_notify && good 'Account lockout enabled - now test sudo in a new terminal'
            fi
        fi
    fi
}

# -------------------------------------------------------------------- ssh ---

do_ssh() {
    section 'SSH'
    local cfg=/etc/ssh/sshd_config unit=ssh
    if [[ ! -f $cfg ]]; then good 'OpenSSH server is not installed'; return; fi
    systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service' && unit=sshd
    mkdir -p /run/sshd

    info "OpenSSH server is installed (service active: $(systemctl is-active "$unit" 2>/dev/null))"
    sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|permitemptypasswords|x11forwarding|maxauthtries) ' | sed 's/^/    /'
    [[ $AUDIT -eq 1 ]] && return

    if is_required ssh; then
        good 'Keeping SSH - the README requires it. Hardening it instead.'
    elif ! confirm 'Does the README list SSH as a required service? (y = keep and harden, n = offer to disable)' risky; then
        if confirm '  Stop and disable the SSH server?' risky; then
            systemctl disable --now "$unit" >/dev/null 2>&1
            systemctl disable --now ssh.socket >/dev/null 2>&1
            good 'SSH stopped and disabled'
        fi
        return
    fi

    backup "$cfg"
    local settings='PermitRootLogin no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 4
IgnoreRhosts yes
HostbasedAuthentication no
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
UsePAM yes'
    local tmp key
    tmp=$(mktemp)
    cp "$cfg" "$tmp"
    # Drop any existing top-level copies of these keys, then put ours first:
    # sshd uses the first value it sees.
    while read -r key _; do sed -ri "/^#?[[:space:]]*${key}[[:space:]]/Id" "$tmp"; done <<< "$settings"
    { echo '# --- CyberPatriot hardening ---'; echo "$settings"; echo; cat "$tmp"; } > "$cfg"
    rm -f "$tmp"

    if sshd -t; then
        systemctl restart "$unit" 2>/dev/null
        good 'sshd hardened and restarted'
    else
        cp -a "$BACKUPDIR$cfg" "$cfg"
        bad 'New sshd_config failed validation - original restored'
    fi
}

# --------------------------------------------------------------- firewall ---

do_firewall() {
    section 'Firewall (ufw)'
    if ! command -v ufw >/dev/null 2>&1; then
        warn 'ufw is not installed'
        if [[ $HAVE_APT -eq 1 ]] && confirm '  Install ufw?'; then apt-get install -y -q ufw >/dev/null; fi
        command -v ufw >/dev/null 2>&1 || return
    fi
    ufw status | head -n 1 | sed 's/^/    /'
    info 'Currently listening:'
    ss -tulpnH 2>/dev/null | awk '{ print "      " $1, $5, $7 }' | sort -u

    confirm 'Enable ufw (deny incoming, allow outgoing, logging on)?' || return
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw logging on >/dev/null
    if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
        ufw allow ssh >/dev/null && info 'Allowed SSH (it is running)'
    fi
    local tag ports port
    for tag in $(read_list services.txt); do
        case "$tag" in
            ssh)  ports='22/tcp' ;;
            ftp)  ports='21/tcp' ;;
            web)  ports='80/tcp 443/tcp' ;;
            smb)  ports='139/tcp 445/tcp 137/udp 138/udp' ;;
            dns)  ports='53' ;;
            mail) ports='25/tcp' ;;
            rdp)  ports='3389/tcp' ;;
            vnc)  ports='5900/tcp' ;;
            *)    ports='' ;;
        esac
        for port in $ports; do ufw allow "$port" >/dev/null && info "Allowed $port (README requires $tag)"; done
    done
    if [[ $YES -eq 0 ]]; then
        local extra
        info 'Other README-required services need their ports opened, e.g. 80/tcp 443/tcp 21/tcp'
        read -r -p '  Extra ports to allow (space separated, blank for none): ' extra < /dev/tty
        for port in $extra; do ufw allow "$port" >/dev/null && info "Allowed $port"; done
    fi
    ufw --force enable >/dev/null && good 'ufw enabled'
}

# ----------------------------------------------------------------- kernel ---

do_sysctl() {
    section 'Kernel network settings (sysctl)'
    confirm 'Write /etc/sysctl.d/99-cyberpatriot.conf (syncookies, no redirects/source routing/forwarding, ASLR)?' || return
    cat > /etc/sysctl.d/99-cyberpatriot.conf <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
EOF
    sysctl --system >/dev/null 2>&1 && good 'sysctl settings applied'
}

# --------------------------------------------------------------- packages ---

HACKING_TOOLS='john john-data hydra hydra-gtk nmap zenmap wireshark tshark ophcrack aircrack-ng
netcat-traditional ncat medusa nikto sqlmap kismet ettercap-common ettercap-graphical dsniff
hashcat fcrackzip crack reaver pixiewps yersinia hping3 p0f wifite bettercap'
SERVERS='telnetd inetutils-telnetd rsh-server nis tftpd-hpa atftpd vsftpd proftpd-basic pure-ftpd
apache2 nginx lighttpd samba bind9 snmpd nfs-kernel-server rpcbind dovecot-core postfix exim4
squid cups mysql-server mariadb-server postgresql tightvncserver x11vnc xrdp'
OTHER='transmission-gtk transmission-daemon deluge qbittorrent ktorrent amule vuze
freeciv wesnoth minetest openarena aisleriot gnome-mines gnome-sudoku gnome-mahjongg
nethack-console steam'

purge_from_list() {
    local label="$1" pkg tag found=0; shift
    for pkg in "$@"; do
        is_installed "$pkg" || continue
        found=1
        tag=$(pkg_tag "$pkg")
        if [[ -n "$tag" ]] && is_required "$tag"; then
            good "Keeping $pkg - the README requires '$tag'"
            continue
        fi
        warn "$label installed: $pkg"
        if confirm "  Purge $pkg?" risky; then
            apt-get purge -y -q "$pkg" >/dev/null && good "Purged $pkg"
        fi
    done
    [[ $found -eq 0 ]] && good "No $label packages found"
}

do_packages() {
    section 'Unwanted packages'
    if [[ $HAVE_APT -eq 0 ]]; then warn 'Not an apt-based system - review packages by hand'; return; fi
    info 'Answer N for anything the README lists as required (web server, FTP, Samba...).'
    # shellcheck disable=SC2086
    purge_from_list 'Hacking tool' $HACKING_TOOLS
    # shellcheck disable=SC2086
    purge_from_list 'Server/service' $SERVERS
    # shellcheck disable=SC2086
    purge_from_list 'Game/P2P' $OTHER
    [[ $AUDIT -eq 0 ]] && apt-get autoremove -y -q >/dev/null 2>&1
}

# ---------------------------------------------------------------- updates ---

do_updates() {
    section 'Updates'
    if [[ $HAVE_APT -eq 0 ]]; then warn 'Not an apt-based system - update by hand'; return; fi
    if confirm 'Turn on daily automatic security updates?'; then
        is_installed unattended-upgrades || apt-get install -y -q unattended-upgrades >/dev/null
        backup /etc/apt/apt.conf.d/20auto-upgrades
        cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
        good 'Automatic updates enabled'
    fi
    if confirm 'Run a full apt upgrade now? (slow - can run while you do other things)' risky; then
        apt-get update -q && apt-get upgrade -y -q && good 'System upgraded'
    fi
}

# ------------------------------------------------------------------- misc ---

do_misc() {
    section 'File permissions, guest login, auditd'
    if confirm 'Fix ownership/permissions on passwd, group, shadow, gshadow?'; then
        chown root:root /etc/passwd /etc/group
        chmod 644 /etc/passwd /etc/group
        local group=root
        getent group shadow >/dev/null && group=shadow
        chown root:"$group" /etc/shadow /etc/gshadow
        chmod 640 /etc/shadow /etc/gshadow
        good 'Permissions fixed'
    fi

    if [[ -d /etc/lightdm ]] && confirm 'Disable the LightDM guest session?'; then
        mkdir -p /etc/lightdm/lightdm.conf.d
        printf '[Seat:*]\nallow-guest=false\n' > /etc/lightdm/lightdm.conf.d/50-no-guest.conf
        good 'Guest session disabled (takes effect at next login screen)'
    fi

    if [[ $HAVE_APT -eq 1 ]] && confirm 'Install and enable auditd?'; then
        is_installed auditd || apt-get install -y -q auditd >/dev/null
        systemctl enable --now auditd >/dev/null 2>&1 && good 'auditd running'
    fi
}

# ----------------------------------------------------------------- report ---

do_report() {
    section 'Read-only report (nothing is changed or deleted)'
    echo "CyberPatriot report $STAMP on $(hostname)" > "$REPORT"

    report 'Media files under /home' "$(find /home -type f \( \
        -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.avi' -o -iname '*.mkv' -o -iname '*.mov' -o \
        -iname '*.wav' -o -iname '*.flac' -o -iname '*.wmv' -o -iname '*.m4a' -o -iname '*.ogg' -o \
        -iname '*.aac' -o -iname '*.mpg' -o -iname '*.mpeg' \) -not -path '*/.cache/*' 2>/dev/null)"

    report 'Scripts / archives / binaries under /home' "$(find /home -type f \( \
        -iname '*.sh' -o -iname '*.py' -o -iname '*.pl' -o -iname '*.zip' -o -iname '*.tar*' -o \
        -iname '*.deb' -o -iname '*.exe' -o -iname '*.torrent' -o -perm -u+x \) \
        -not -path '*/.cache/*' -not -path '*/.local/share/*' -not -path '*/.config/*' 2>/dev/null)"

    report 'System accounts with a login shell' "$(awk -F: \
        '$3 < 1000 && $1 != "root" && $1 != "sync" && $7 !~ /(nologin|false)$/ { print $1 " -> " $7 }' /etc/passwd)"

    report 'sudoers entries with NOPASSWD or !authenticate' \
        "$(grep -rEHn 'NOPASSWD|!authenticate' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v ':[0-9]*:[[:space:]]*#')"

    report 'SSH authorized_keys files' "$(find /home /root -name authorized_keys -size +0 2>/dev/null)"

    report 'User crontabs' "$(ls -1 /var/spool/cron/crontabs 2>/dev/null | sed 's|^|/var/spool/cron/crontabs/|')"

    report 'Cron entries (system)' "$(grep -rEHv '^[[:space:]]*(#|$)' /etc/crontab /etc/cron.d 2>/dev/null)"

    report 'rc.local commands' "$(grep -Ev '^[[:space:]]*(#|$|exit 0)' /etc/rc.local 2>/dev/null)"

    report 'Listening ports' "$(ss -tulpnH 2>/dev/null | awk '{ print $1, $5, $7 }' | sort -u)"

    report 'Non-default /etc/hosts entries' \
        "$(grep -Ev '^[[:space:]]*(#|$)' /etc/hosts | grep -Ev 'localhost|ip6-|127\.0\.1\.1')"

    report 'SUID/SGID files outside the usual system dirs' \
        "$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) \
            -not -path '/usr/bin/*' -not -path '/usr/sbin/*' -not -path '/usr/lib/*' \
            -not -path '/usr/libexec/*' -not -path '/bin/*' -not -path '/sbin/*' \
            -not -path '/snap/*' -not -path '/var/lib/snapd/*' 2>/dev/null)"

    info ''
    info "Full report: $REPORT"
}

# ------------------------------------------------------------------- menu ---

NAMES=('Users and groups' 'Password policy' 'SSH' 'Firewall' 'Kernel network settings'
       'Unwanted packages' 'Updates' 'Permissions, guest login, auditd'
       'Report (media, cron, ports, sudoers, SUID)')
FUNCS=(do_users do_password_policy do_ssh do_firewall do_sysctl do_packages do_updates do_misc do_report)

run_all() { local fn; for fn in "${FUNCS[@]}"; do "$fn"; done; }

reminders() {
    section 'Still on you (the script cannot do these)'
    info '- Forensics questions (do them BEFORE removing anything)'
    info '- Delete the media files and review everything else in the report'
    info '- Harden README-required services (apache, vsftpd, samba, mysql...) in their own configs'
    info '- Browser settings and updates for README-required software'
    info '- Software & Updates app: enable security updates / daily checks if the scorer wants the GUI setting'
    info "- Backups of every edited file: $BACKUPDIR"
}

printf '\033[36mCyberPatriot Linux hardening\033[0m\n'
[[ $AUDIT -eq 1 ]] && warn 'AUDIT ONLY - nothing will be changed'
warn 'Finish the forensics questions before changing users, services or software.'

[[ -n "$README_FILE" ]] && import_readme "$README_FILE"

if [[ $ALL -eq 1 ]]; then
    run_all
else
    while true; do
        echo
        for i in "${!NAMES[@]}"; do echo "  $((i + 1))) ${NAMES[$i]}"; done
        echo '  F) Forensics questions helper (do these first)'
        echo '  R) Read the README (paste it, fills in users/admins/services)'
        echo '  A) Run everything in order'
        echo '  Q) Quit'
        read -r -p 'Choose: ' choice < /dev/tty
        case "$choice" in
            [qQ]) break ;;
            [rR]) import_readme ;;
            [fF]) do_forensics ;;
            [aA]) run_all ;;
            [1-9]) if [[ $choice -le ${#FUNCS[@]} ]]; then "${FUNCS[$((choice - 1))]}"; else warn 'Not an option'; fi ;;
            *) warn 'Not an option' ;;
        esac
    done
fi
reminders
