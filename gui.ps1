#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Window front end for harden.ps1. Start it with run-windows.bat.

.DESCRIPTION
    1. Paste the image README and click "Read README".
    2. Check the admins / users / required services it found (edit if wrong).
    3. Tick the sections to run and click Run.
    Every change still asks first, in a Yes/No box.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

try {

# Load the section functions without running the console menu.
. (Join-Path $PSScriptRoot 'harden.ps1') -Library

$script:SkipRest = $false

# ------------------------------------------------------------- controls ---

function New-Label($text, $x, $y, $w = 200, $h = 18) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $text
    $label.Location = New-Object System.Drawing.Point($x, $y)
    $label.Size = New-Object System.Drawing.Size($w, $h)
    return $label
}

function New-TextArea($x, $y, $w, $h) {
    $box = New-Object System.Windows.Forms.TextBox
    $box.Multiline = $true
    $box.ScrollBars = 'Vertical'
    $box.AcceptsReturn = $true
    $box.Font = New-Object System.Drawing.Font('Consolas', 9)
    $box.Location = New-Object System.Drawing.Point($x, $y)
    $box.Size = New-Object System.Drawing.Size($w, $h)
    return $box
}

function New-Button($text, $x, $y, $w, $h = 28) {
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $text
    $button.Location = New-Object System.Drawing.Point($x, $y)
    $button.Size = New-Object System.Drawing.Size($w, $h)
    return $button
}

$Form = New-Object System.Windows.Forms.Form
$Form.Text = 'CyberPatriot Windows hardening'
$Form.ClientSize = New-Object System.Drawing.Size(1100, 760)
$Form.MinimumSize = New-Object System.Drawing.Size(1116, 600)
$Form.StartPosition = 'CenterScreen'

$ReadmeBox   = New-TextArea 12  32 400 280
$AdminsBox   = New-TextArea 424 32 140 280
$UsersBox    = New-TextArea 572 32 140 280
$ServicesBox = New-TextArea 720 32 130 200
$ReadmeBox.MaxLength = 0
$ReadmeBox.WordWrap = $true

$ReadButton = New-Button 'Read README  >>' 12 320 400
$SaveButton = New-Button 'Save lists' 424 320 288
$ForensicsButton = New-Button 'Forensics...' 720 320 130

$SectionList = New-Object System.Windows.Forms.CheckedListBox
$SectionList.Location = New-Object System.Drawing.Point(862, 32)
$SectionList.Size = New-Object System.Drawing.Size(226, 170)
$SectionList.CheckOnClick = $true
foreach ($key in $Sections.Keys) { [void]$SectionList.Items.Add($Sections[$key].Name, $true) }

$AuditCheck = New-Object System.Windows.Forms.CheckBox
$AuditCheck.Text = 'Audit only (change nothing)'
$AuditCheck.Location = New-Object System.Drawing.Point(862, 208)
$AuditCheck.Size = New-Object System.Drawing.Size(226, 20)
$AuditCheck.Checked = $true

$YesCheck = New-Object System.Windows.Forms.CheckBox
$YesCheck.Text = 'Do not ask about safe changes'
$YesCheck.Location = New-Object System.Drawing.Point(862, 230)
$YesCheck.Size = New-Object System.Drawing.Size(226, 20)

$RunButton  = New-Button 'Run' 862 258 226 36
$RunButton.Font = New-Object System.Drawing.Font($Form.Font, [System.Drawing.FontStyle]::Bold)
$LogsButton = New-Button 'Open logs folder' 862 320 226

$LogBox = New-Object System.Windows.Forms.RichTextBox
$LogBox.Location = New-Object System.Drawing.Point(12, 376)
$LogBox.Size = New-Object System.Drawing.Size(1076, 372)
$LogBox.Anchor = 'Top, Bottom, Left, Right'
$LogBox.ReadOnly = $true
$LogBox.BackColor = [System.Drawing.Color]::White
$LogBox.Font = New-Object System.Drawing.Font('Consolas', 9.5)

$Form.Controls.AddRange([System.Windows.Forms.Control[]]@(
    (New-Label '1. Paste the image README here' 12 10 400),
    $ReadmeBox, $ReadButton,
    (New-Label '2. Check: administrators' 424 10 140),
    (New-Label 'standard users' 572 10 140),
    (New-Label 'required services' 720 10 130),
    $AdminsBox, $UsersBox, $ServicesBox, $SaveButton, $ForensicsButton,
    (New-Label "One tag per line:`n$($ServiceTags.Keys -join ' ')" 720 238 130 74),
    (New-Label '3. Choose what to run' 862 10 226),
    $SectionList, $AuditCheck, $YesCheck, $RunButton, $LogsButton,
    (New-Label 'Log' 12 356 200),
    $LogBox
))

# ------------------------------------- replace the console input/output ---

function Add-Log([string]$Text, [string]$Color = 'Black') {
    $LogBox.SelectionStart = $LogBox.TextLength
    $LogBox.SelectionLength = 0
    $LogBox.SelectionColor = [System.Drawing.Color]::FromName($Color)
    $LogBox.AppendText($Text + "`r`n")
    $LogBox.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

function Section($text) { Add-Log ''; Add-Log "=== $text ===" 'DarkCyan' }
function Info($text)    { Add-Log "    $text" }
function Good($text)    { Add-Log "[ok] $text" 'ForestGreen' }
function Warn($text)    { Add-Log "[!!] $text" 'DarkOrange' }
function Bad($text)     { Add-Log "[xx] $text" 'Firebrick' }

function Confirm-Change {
    param([string]$Question, [switch]$Risky)
    $Question = $Question.Trim()
    if ($AuditCheck.Checked) { Add-Log "    (audit only) skipped: $Question" 'Gray'; return $false }
    if ($script:SkipRest)    { Add-Log "    skipped: $Question" 'Gray'; return $false }
    if ($YesCheck.Checked -and -not $Risky) { Add-Log "    auto-yes: $Question" 'Gray'; return $true }

    $icon = 'Question'
    if ($Risky) { $icon = 'Warning' }
    $answer = [System.Windows.Forms.MessageBox]::Show($Form,
        "$Question`n`nCancel = answer No to everything else in this run.",
        'Confirm change', 'YesNoCancel', $icon)
    if ($answer -eq 'Cancel') {
        $script:SkipRest = $true
        Add-Log '    Cancelled - skipping every remaining question in this run' 'Gray'
        return $false
    }
    $isYes = ($answer -eq 'Yes')
    if ($isYes) { Add-Log "    YES: $Question" 'Gray' } else { Add-Log "    no:  $Question" 'Gray' }
    return $isYes
}

function Read-NewPassword {
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = 'New password for all other users'
    $dialog.ClientSize = New-Object System.Drawing.Size(380, 120)
    $dialog.FormBorderStyle = 'FixedDialog'
    $dialog.StartPosition = 'CenterParent'
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false

    $box = New-Object System.Windows.Forms.TextBox
    $box.Location = New-Object System.Drawing.Point(12, 48)
    $box.Size = New-Object System.Drawing.Size(356, 22)
    $ok = New-Button 'Set password' 172 82 100
    $ok.DialogResult = 'OK'
    $cancel = New-Button 'Cancel' 278 82 90
    $cancel.DialogResult = 'Cancel'
    $dialog.Controls.AddRange([System.Windows.Forms.Control[]]@(
        (New-Label '12+ characters with upper, lower, number and symbol. Shown in the clear so you can check it - write it down.' 12 8 356 36),
        $box, $ok, $cancel))
    $dialog.AcceptButton = $ok
    $dialog.CancelButton = $cancel

    $result = $dialog.ShowDialog($Form)
    $text = $box.Text
    $dialog.Dispose()
    if ($result -ne 'OK' -or -not $text) { return $null }
    return (ConvertTo-SecureString $text -AsPlainText -Force)
}

# -------------------------------------------------------------- actions ---

function Get-BoxLines($box) {
    return @($box.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
}

function Set-BoxLines($box, $lines) {
    $box.Text = (@($lines) -join "`r`n")
}

function Save-FromBoxes {
    $services = Get-BoxLines $ServicesBox
    foreach ($tag in $services) {
        if (-not $ServiceTags.Contains($tag.ToLower())) { Warn "'$tag' is not a service tag I know - it will be ignored" }
    }
    Save-Lists (Get-BoxLines $AdminsBox) (Get-BoxLines $UsersBox) ($services | ForEach-Object { $_.ToLower() }) $ReadmeBox.Text
}

$ReadButton.Add_Click({
    Section 'Reading the README'
    if (-not $ReadmeBox.Text.Trim()) { Bad 'The README box is empty - paste the README text into it first.'; return }
    $result = ConvertFrom-Readme $ReadmeBox.Text
    Set-BoxLines $AdminsBox $result.Admins
    Set-BoxLines $UsersBox $result.Users
    Set-BoxLines $ServicesBox $result.Services
    Show-ReadmeResult $result
    Save-FromBoxes
    Info 'Lists filled in and saved. Fix anything that is wrong, then Run.'
})

$SaveButton.Add_Click({
    Save-FromBoxes
    Good 'Lists saved to admins.txt / users.txt / services.txt'
})

$LogsButton.Add_Click({ Start-Process explorer.exe $LogDir })

$RunButton.Add_Click({
    Save-FromBoxes
    $script:SkipRest = $false
    $RunButton.Enabled = $false
    $ReadButton.Enabled = $false
    try {
        if ($AuditCheck.Checked) { Warn 'AUDIT ONLY - nothing will be changed. Untick "Audit only" to make changes.' }
        $keys = @($Sections.Keys)
        for ($i = 0; $i -lt $keys.Count; $i++) {
            if (-not $SectionList.GetItemChecked($i)) { continue }
            $entry = $Sections[$keys[$i]]
            try {
                # Anything a section writes that is not already logged (mostly errors) lands here.
                & $entry.Run 2>&1 | ForEach-Object {
                    if ($_ -is [System.Management.Automation.ErrorRecord]) { Add-Log "    error: $_" 'Firebrick' }
                    else { Add-Log "    $_" }
                }
            } catch {
                Bad "$($entry.Name) stopped: $($_.Exception.Message)"
            }
        }
        Show-Reminders
        Add-Log ''
        Add-Log 'Finished.' 'DarkCyan'
    } finally {
        $RunButton.Enabled = $true
        $ReadButton.Enabled = $true
        $LogBox.Text | Set-Content -Path (Join-Path $LogDir "harden-windows-gui-$Stamp.log")
    }
})

# ----------------------------------------------------- forensics window ---
#
# Built once here (not inside a function) so the click handlers can see the
# controls. It only gathers evidence; you read the question and type the answer.

$FxForm = New-Object System.Windows.Forms.Form
$FxForm.Text = 'Forensics questions'
$FxForm.ClientSize = New-Object System.Drawing.Size(920, 720)
$FxForm.FormBorderStyle = 'FixedDialog'
$FxForm.MaximizeBox = $false
$FxForm.StartPosition = 'CenterParent'

$FxList = New-Object System.Windows.Forms.ListBox
$FxList.Location = New-Object System.Drawing.Point(12, 32)
$FxList.Size = New-Object System.Drawing.Size(250, 160)
$FxList.HorizontalScrollbar = $true

$FxQuestion = New-TextArea 274 32 634 160
$FxQuestion.ReadOnly = $true
$FxQuestion.BackColor = [System.Drawing.Color]::White

$FxInput = New-Object System.Windows.Forms.TextBox
$FxInput.Location = New-Object System.Drawing.Point(12, 222)
$FxInput.Size = New-Object System.Drawing.Size(800, 22)
$FxBrowse = New-Button 'Browse...' 818 220 90 26

$FxClues  = New-Button 'Look up what the question names' 12 252 230
$FxFile   = New-Button 'File info + hashes' 248 252 150
$FxDecode = New-Button 'Decode text' 404 252 120
$FxFind   = New-Button 'Find file by name' 530 252 150
$FxUser   = New-Button 'User info' 686 252 110
$FxReload = New-Button 'Refresh list' 802 252 106

$FxResult = New-TextArea 12 288 896 290
$FxResult.ReadOnly = $true
$FxResult.BackColor = [System.Drawing.Color]::White
$FxResult.WordWrap = $false
$FxResult.ScrollBars = 'Both'

$FxAnswer = New-TextArea 12 608 700 60
$FxSave   = New-Button 'Write answer into the file' 724 608 184 60
$FxStatus = New-Label '' 12 678 896 34

$FxForm.Controls.AddRange([System.Windows.Forms.Control[]]@(
    (New-Label 'Question files found' 12 10 250),
    (New-Label 'Question' 274 10 300),
    $FxList, $FxQuestion,
    (New-Label 'Tool input: a file path, some encoded text, a file name, or a user name' 12 202 600),
    $FxInput, $FxBrowse, $FxClues, $FxFile, $FxDecode, $FxFind, $FxUser, $FxReload,
    $FxResult,
    (New-Label 'Your answer (one per line if the file has several ANSWER: lines)' 12 588 600),
    $FxAnswer, $FxSave, $FxStatus
))

$script:FxFiles = @()

function Set-FxResult($lines) {
    $FxResult.Text = (@($lines) -join "`r`n")
    [System.Windows.Forms.Application]::DoEvents()
}

function Get-FxSelectedFile {
    if ($FxList.SelectedIndex -lt 0 -or $FxList.SelectedIndex -ge $script:FxFiles.Count) { return $null }
    return $script:FxFiles[$FxList.SelectedIndex]
}

function Update-FxQuestion {
    $file = Get-FxSelectedFile
    if (-not $file) { $FxQuestion.Text = ''; return }
    $FxQuestion.Text = (@(Get-Content -LiteralPath $file) -join "`r`n")
}

function Update-FxList {
    $script:FxFiles = @(Get-ForensicsFiles)
    $FxList.Items.Clear()
    foreach ($file in $script:FxFiles) {
        # Show "user\file name" so questions on different desktops can be told apart.
        $owner = $file.Split('\')[2]
        [void]$FxList.Items.Add("$owner\$(Split-Path $file -Leaf)")
    }
    if ($script:FxFiles.Count -eq 0) {
        $FxQuestion.Text = ''
        Set-FxResult 'No files with "forensic" in the name were found on any Desktop.'
    } else {
        $FxList.SelectedIndex = 0
    }
}

$FxList.Add_SelectedIndexChanged({
    Update-FxQuestion
    $FxAnswer.Text = ''
    $FxStatus.Text = ''
    if ($FxQuestion.Text) {
        Set-FxResult 'Looking up what the question names...'
        Set-FxResult (Get-ForensicsClues $FxQuestion.Text)
    }
})

$FxClues.Add_Click({
    Set-FxResult 'Looking up what the question names...'
    Set-FxResult (Get-ForensicsClues $FxQuestion.Text)
})
$FxFile.Add_Click({ Set-FxResult (Get-FileSummary $FxInput.Text) })
$FxDecode.Add_Click({ Set-FxResult (Invoke-DecodeAll $FxInput.Text) })
$FxUser.Add_Click({ Set-FxResult (Get-UserSummary $FxInput.Text) })
$FxReload.Add_Click({ Update-FxList })
$FxFind.Add_Click({
    Set-FxResult 'Searching C: (everything except C:\Windows). This can take a minute and the window will not respond until it is done...'
    Set-FxResult (Find-FilesByName $FxInput.Text)
})
$FxBrowse.Add_Click({
    $picker = New-Object System.Windows.Forms.OpenFileDialog
    $picker.Title = 'Pick a file to inspect'
    if ($picker.ShowDialog($FxForm) -eq 'OK') {
        $FxInput.Text = $picker.FileName
        Set-FxResult (Get-FileSummary $picker.FileName)
    }
    $picker.Dispose()
})
$FxSave.Add_Click({
    $file = Get-FxSelectedFile
    if (-not $file) { $FxStatus.Text = 'Pick a question file first.'; return }
    $answers = @($FxAnswer.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($answers.Count -eq 0) { $FxStatus.Text = 'Type your answer first.'; return }
    try {
        $count = Set-ForensicsAnswer $file $answers
        Update-FxQuestion
        $FxStatus.Text = "Wrote $count answer(s) into $(Split-Path $file -Leaf). Check the question box to confirm it looks right. The untouched original is in the logs folder."
        Add-Log "    Forensics answer written to $file" 'Gray'
    } catch {
        $FxStatus.Text = "Could not write the file: $($_.Exception.Message)"
    }
})

$ForensicsButton.Add_Click({
    Update-FxList
    [void]$FxForm.ShowDialog($Form)
})

# ----------------------------------------------------------------- start ---

Set-BoxLines $AdminsBox (Read-List 'admins.txt')
Set-BoxLines $UsersBox (Read-List 'users.txt')
Set-BoxLines $ServicesBox (Read-List 'services.txt')
$savedReadme = Join-Path $ScriptDir 'readme.txt'
if (Test-Path $savedReadme) { $ReadmeBox.Text = [string](Get-Content $savedReadme -Raw) }

Add-Log 'Finish the forensics questions before changing users, services or software ("Forensics..." button).' 'DarkOrange'
Add-Log "Logged in as: $env:USERNAME"
Add-Log 'Paste the README on the left, click "Read README", check the lists, then Run.'
Add-Log '"Audit only" starts ticked: the first Run only reports. Untick it to make changes.'

[void]$Form.ShowDialog()

} catch {
    [void][System.Windows.Forms.MessageBox]::Show(
        "The GUI hit an error:`n`n$($_.Exception.Message)`n`n$($_.ScriptStackTrace)`n`nYou can still use the console version: harden.ps1",
        'CyberPatriot hardening', 'OK', 'Error')
}
