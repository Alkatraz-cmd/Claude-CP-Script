# Forensics question helper. Loaded by harden.ps1 (and so by gui.ps1).
#
# Every forensics question is different, so this cannot answer them for you.
# What it does: finds the question files, pulls out the things a question
# names (files, users, encoded text) and looks them up, gives you the common
# tools (hashes, decoders, file search, user info), and writes your answer
# onto the ANSWER: line. You still read the question and pick the answer.

function Get-ForensicsFiles {
    $places = 'C:\Users\*\Desktop', 'C:\Users\*\OneDrive\Desktop'
    $found = Get-ChildItem -Path $places -Filter '*orensic*' -File -Force -ErrorAction SilentlyContinue
    return @($found | Sort-Object FullName | ForEach-Object { $_.FullName })
}

function Test-PrintableText([string]$Text) {
    return ($Text.Length -gt 0 -and $Text -notmatch '[^\x09\x0A\x0D\x20-\x7E]')
}

function Get-FileSummary([string]$Path) {
    $Path = $Path.Trim().Trim('"')
    $out = New-Object System.Collections.Generic.List[string]
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { $out.Add("Not found: $Path"); return $out.ToArray() }

    $item = Get-Item -LiteralPath $Path -Force
    $out.Add("Path:     $($item.FullName)")
    try { $out.Add("Owner:    $((Get-Acl -LiteralPath $Path -ErrorAction Stop).Owner)") } catch { $out.Add('Owner:    (could not read)') }
    $out.Add("Created:  $($item.CreationTime)")
    $out.Add("Modified: $($item.LastWriteTime)")
    $out.Add("Attributes: $($item.Attributes)")

    if ($item.PSIsContainer) {
        $children = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
        $out.Add("Folder with $($children.Count) items:")
        $children | Select-Object -First 40 | ForEach-Object { $out.Add("  $($_.Name)") }
    } else {
        $out.Add("Size:     $($item.Length) bytes")
        if ($item.Length -lt 1GB) {
            foreach ($algorithm in 'MD5', 'SHA1', 'SHA256') {
                try { $out.Add(('{0,-9} {1}' -f "${algorithm}:", (Get-FileHash -LiteralPath $Path -Algorithm $algorithm -ErrorAction Stop).Hash)) }
                catch { $out.Add("${algorithm}: (could not read file)") }
            }
        }
        # Alternate data streams are a favorite hiding place.
        $streams = @(Get-Item -LiteralPath $Path -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' })
        foreach ($stream in $streams) {
            $out.Add("Hidden data stream '$($stream.Stream)' ($($stream.Length) bytes):")
            Get-Content -LiteralPath $Path -Stream $stream.Stream -TotalCount 10 -ErrorAction SilentlyContinue |
                ForEach-Object { $out.Add("  $_") }
        }
    }
    return $out.ToArray()
}

function Get-UserSummary([string]$Name) {
    $Name = $Name.Trim()
    $out = New-Object System.Collections.Generic.List[string]
    $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if (-not $user) { $out.Add("No local user named '$Name'"); return $out.ToArray() }

    $groups = Get-LocalGroup | Where-Object {
        try { @(Get-LocalGroupMember -Group $_.Name -ErrorAction Stop | ForEach-Object { $_.SID.Value }) -contains $user.SID.Value }
        catch { $false }
    } | ForEach-Object { $_.Name }

    $out.Add("User:        $($user.Name)")
    $out.Add("Full name:   $($user.FullName)")
    $out.Add("Description: $($user.Description)")
    $out.Add("SID:         $($user.SID.Value)")
    $out.Add("Enabled:     $($user.Enabled)")
    $out.Add("Groups:      $($groups -join ', ')")
    $out.Add("Last logon:  $($user.LastLogon)")
    $out.Add("Password last set: $($user.PasswordLastSet)")
    $out.Add("Profile folder exists: $(Test-Path "C:\Users\$($user.Name)")")
    return $out.ToArray()
}

# Tries every common encoding on a piece of text and shows the ones that
# come out readable. -Quiet leaves out the ones that always "work" (ROT13...).
function Invoke-DecodeAll([string]$Text, [switch]$Quiet) {
    $text = $Text.Trim()
    $out = New-Object System.Collections.Generic.List[string]
    if (-not $text) { return $out.ToArray() }

    try {
        $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($text))
        if (Test-PrintableText $decoded) { $out.Add("Base64  -> $decoded") }
    } catch { }

    $hex = $text -replace '0x', '' -replace '[\s:,\-]', ''
    if ($hex.Length -ge 4 -and $hex -match '^([0-9A-Fa-f]{2})+$') {
        $chars = for ($i = 0; $i -lt $hex.Length; $i += 2) { [char][Convert]::ToByte($hex.Substring($i, 2), 16) }
        $decoded = -join $chars
        if (Test-PrintableText $decoded) { $out.Add("Hex     -> $decoded") }
    }

    $bits = $text -replace '\s', ''
    if ($bits.Length -ge 8 -and $bits.Length % 8 -eq 0 -and $bits -match '^[01]+$') {
        $chars = for ($i = 0; $i -lt $bits.Length; $i += 8) { [char][Convert]::ToByte($bits.Substring($i, 8), 2) }
        $decoded = -join $chars
        if (Test-PrintableText $decoded) { $out.Add("Binary  -> $decoded") }
    }

    if ($text -match '^(\d{2,3}[\s,]+)+\d{2,3}$') {
        $numbers = $text -split '[\s,]+' | ForEach-Object { [int]$_ }
        if (-not ($numbers | Where-Object { $_ -gt 126 -or $_ -lt 9 })) {
            $out.Add("Decimal -> $(-join ($numbers | ForEach-Object { [char]$_ }))")
        }
    }

    $unescaped = [Uri]::UnescapeDataString($text)
    if ($unescaped -ne $text) { $out.Add("URL     -> $unescaped") }

    if (-not $Quiet) {
        $rot13 = -join ($text.ToCharArray() | ForEach-Object {
            $code = [int]$_
            if ($code -ge 65 -and $code -le 90) { [char](($code - 65 + 13) % 26 + 65) }
            elseif ($code -ge 97 -and $code -le 122) { [char](($code - 97 + 13) % 26 + 97) }
            else { $_ }
        })
        $out.Add("ROT13   -> $rot13")
        $reversed = $text.ToCharArray()
        [array]::Reverse($reversed)
        $out.Add("Reversed-> $(-join $reversed)")
        if ($out.Count -eq 2) { $out.Insert(0, '(not valid Base64, hex, binary, decimal or URL encoding)') }
    }
    return $out.ToArray()
}

function Find-FilesByName([string]$Pattern) {
    $Pattern = $Pattern.Trim().Trim('"')
    if (-not $Pattern) { return @('Type a file name (or part of one) first.') }
    if ($Pattern -notmatch '[*?]') { $Pattern = "*$Pattern*" }
    # Everything on C: except the Windows folder, which is huge and rarely the answer.
    $roots = Get-ChildItem 'C:\' -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'Windows' }
    $hits = $roots | ForEach-Object {
        Get-ChildItem -LiteralPath $_.FullName -Recurse -Force -Filter $Pattern -ErrorAction SilentlyContinue
    } | Select-Object -First 100 | ForEach-Object { $_.FullName }
    if (-not $hits) { return @("Nothing matching $Pattern outside C:\Windows.") }
    return @($hits)
}

# Looks up everything the question text names. Returns lines of text.
function Get-ForensicsClues([string]$Text) {
    $out = New-Object System.Collections.Generic.List[string]
    $question = (($Text -split "`r?`n") | Where-Object { $_ -notmatch '^\s*ANSWER' }) -join "`n"

    # --- file and folder paths. A path can contain spaces, so start with the
    #     longest candidate and trim words off the end until something exists.
    $seen = @{}
    foreach ($match in [regex]::Matches($question, '[A-Za-z]:\\[^\r\n"<>|?*]+')) {
        $candidate = $match.Value
        while ($candidate) {
            $probe = $candidate.TrimEnd(' ', '.', ',', ';', ':', ')', '?', '!', "'")
            if ($probe.Length -gt 3 -and (Test-Path -LiteralPath $probe)) {
                if (-not $seen[$probe]) {
                    $seen[$probe] = $true
                    $out.Add('--- Named in the question:')
                    foreach ($line in @(Get-FileSummary $probe)) { $out.Add($line) }
                    $out.Add('')
                }
                break
            }
            $cut = $probe.LastIndexOf(' ')
            if ($cut -lt 0) {
                $out.Add("--- The question names a path that does not exist (deleted? hidden? typo?): $($match.Value.Trim())")
                $out.Add('')
                break
            }
            $candidate = $probe.Substring(0, $cut)
        }
    }

    # --- local users mentioned by name
    foreach ($user in (Get-LocalUser)) {
        $pattern = '(?<!\w)' + [regex]::Escape($user.Name) + '(?!\w)'
        if ($question -match $pattern) {
            $out.Add('--- User mentioned in the question:')
            foreach ($line in @(Get-UserSummary $user.Name)) { $out.Add($line) }
            $out.Add('')
        }
    }

    # --- things that look encoded
    $encodedPatterns = '[A-Za-z0-9+/]{16,}={0,2}', '(?:[0-9A-Fa-f]{2}[ :]){7,}[0-9A-Fa-f]{2}', '(?:[01]{8} ?){4,}'
    foreach ($pattern in $encodedPatterns) {
        foreach ($match in [regex]::Matches($question, $pattern)) {
            $decoded = @(Invoke-DecodeAll $match.Value -Quiet)
            if ($decoded.Count) {
                $out.Add("--- This looks encoded: $($match.Value.Trim())")
                foreach ($line in $decoded) { $out.Add($line) }
                $out.Add('')
            }
        }
    }

    # --- topic hints
    if ($question -match '\bports?\b|listening') {
        $out.Add('--- The question mentions ports. Listening TCP ports:')
        Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort -Unique | ForEach-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            $out.Add("  $($_.LocalPort) -> $($process.ProcessName) (pid $($_.OwningProcess)) $($process.Path)")
        }
        $out.Add('')
    }
    if ($question -match '\bshare[sd]?\b') {
        $out.Add('--- The question mentions shares:')
        Get-SmbShare -ErrorAction SilentlyContinue | ForEach-Object { $out.Add("  $($_.Name) -> $($_.Path)") }
        $out.Add('')
    }
    if ($question -match 'scheduled|\btasks?\b') {
        $out.Add('--- The question mentions tasks. Non-Microsoft scheduled tasks:')
        Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
            $out.Add("  $($_.TaskPath)$($_.TaskName) -> $(($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; ')")
        }
        $out.Add('')
    }
    if ($question -match '\bgroups?\b') {
        $out.Add('--- The question mentions groups. Local groups that have members:')
        foreach ($group in (Get-LocalGroup)) {
            try { $members = @(Get-LocalGroupMember -Group $group.Name -ErrorAction Stop | ForEach-Object { $_.Name.Split('\')[-1] }) } catch { $members = @() }
            if ($members.Count) { $out.Add("  $($group.Name): $($members -join ', ')") }
        }
        $out.Add('')
    }

    if ($out.Count -eq 0) {
        $out.Add('Nothing in this question could be looked up automatically.')
        $out.Add('Read it and use the tools: file info + hashes, decode text, find file, user info.')
    }
    return $out.ToArray()
}

# Fills the ANSWER: lines, in order, with the answers given. Returns how many it wrote.
function Set-ForensicsAnswer([string]$Path, [string[]]$Answers) {
    $Answers = @($Answers | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($Answers.Count -eq 0) { return 0 }

    # Keep the untouched original once, in case an answer goes in wrong.
    $backup = Join-Path $LogDir ((Split-Path $Path -Leaf) + '.original')
    if (-not (Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $Path -Destination $backup }

    # Write the file back in the encoding it came in.
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $encoding = New-Object System.Text.UTF8Encoding($false)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { $encoding = [System.Text.Encoding]::Unicode }
    elseif ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $encoding = New-Object System.Text.UTF8Encoding($true) }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.AddRange([System.IO.File]::ReadAllLines($Path))
    $used = 0
    for ($i = 0; $i -lt $lines.Count -and $used -lt $Answers.Count; $i++) {
        if ($lines[$i] -match '^\s*ANSWER\s*:') { $lines[$i] = "ANSWER: $($Answers[$used])"; $used++ }
    }
    while ($used -lt $Answers.Count) { $lines.Add("ANSWER: $($Answers[$used])"); $used++ }
    [System.IO.File]::WriteAllLines($Path, $lines.ToArray(), $encoding)
    return $used
}

# Text-menu version (the GUI has its own window for this).
function Invoke-ForensicsConsole {
    Section 'Forensics questions'
    $files = @(Get-ForensicsFiles)
    if ($files.Count -eq 0) { Warn 'No files with "forensic" in the name on any Desktop.'; return }

    foreach ($file in $files) {
        Write-Host "`n----- $file" -ForegroundColor Cyan
        Get-Content -LiteralPath $file | ForEach-Object { Info $_ }
        Write-Host "`nClues:" -ForegroundColor Cyan
        @(Get-ForensicsClues ([string](Get-Content -LiteralPath $file -Raw))) | ForEach-Object { Info $_ }

        while ($true) {
            $choice = (Read-Host "`n[a]nswer  [h]ash/file info  [d]ecode  [f]ind file  [u]ser  [n]ext question  [q]uit").Trim().ToLower()
            if ($choice -eq 'n') { break }
            if ($choice -eq 'q') { return }
            switch ($choice) {
                'a' {
                    $answer = Read-Host 'Answer (separate several answers with | )'
                    $count = Set-ForensicsAnswer $file ($answer -split '\|')
                    if ($count) { Good "Wrote $count answer(s) into the file" } else { Warn 'Nothing written' }
                }
                'h' { @(Get-FileSummary (Read-Host 'File or folder path')) | ForEach-Object { Info $_ } }
                'd' { @(Invoke-DecodeAll (Read-Host 'Text to decode')) | ForEach-Object { Info $_ } }
                'f' { Info 'Searching C: (can take a minute)...'; @(Find-FilesByName (Read-Host 'File name or part of it')) | ForEach-Object { Info $_ } }
                'u' { @(Get-UserSummary (Read-Host 'User name')) | ForEach-Object { Info $_ } }
                default { Warn 'Not an option' }
            }
        }
    }
}
