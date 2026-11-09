# Actual production selector/traversal/focus/invoke functions over synthetic UIA nodes.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Diary navigation source parse failed' }
foreach ($name in @('Get-OfflineDiaryNavigationPattern','Find-OfflineControl','Focus-OfflineControl','Test-OfflineFocusRetryable','Find-FocusedOfflineButton','Press-OfflineButton')) {
    $functions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($functions.Count -ne 1) { throw 'Diary navigation function missing' }
    . ([scriptblock]::Create($functions[0].Extent.Text))
}
$acceptance=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-OfflineGuiAcceptance'},$true))
if ($acceptance.Count -ne 1 -or -not $acceptance[0].Extent.Text.Contains('Press-OfflineButton (Get-OfflineDiaryNavigationPattern)')) { throw 'Production diary route does not use the tested selector' }
$diary=[regex]::Unescape('\u65e5\u8bb0'); $pattern=Get-OfflineDiaryNavigationPattern
function Assert-Target { param($Foreground) $script:guards++; if ($script:foreignTarget) { throw 'Foreign target' }; $script:ownedIds=[Collections.Generic.HashSet[int]]::new(); [void]$script:ownedIds.Add(20) }
function Pause-Probe { throw 'Diary navigation unexpectedly waited' }
function Test-OfflineButtonReplacement { throw 'Diary navigation unexpectedly attempted replacement' }
function Get-OfflineReplacementRoot { return $script:root }
function Get-OfflineReplacementWalker { return $script:walker }
function Read-TargetFocus { return @{belongs_to_target=$true;in_document=$true;runtime_id=$script:focused;offscreen=$false} }
function New-DiaryNode([int]$Id,$Type,[string]$Name) {
    $node=[pscustomobject]@{Id=$Id;Children=@();Sibling=$null;Current=[pscustomobject]@{ProcessId=20;ControlType=$Type;Name=$Name;IsEnabled=$true;IsKeyboardFocusable=$true;IsOffscreen=$false}}
    $node | Add-Member ScriptMethod GetRuntimeId { return @([int]$this.Id) }
    $node | Add-Member ScriptMethod SetFocus { $script:focusCalls++; $script:focused=[string]$this.Id }
    $node | Add-Member ScriptMethod TryGetCurrentPattern {
        param($Pattern,$Result)
        if ($Pattern -ne [Windows.Automation.InvokePattern]::Pattern) { throw 'Diary navigation requested another pattern' }
        $action=[pscustomobject]@{}
        $action | Add-Member ScriptMethod Invoke { $script:invokes++ }
        $Result.Value=$action
        return $true
    }
    return $node
}
function Reset-Navigation([string]$Name) {
    $script:guards=0; $script:focusCalls=0; $script:invokes=0; $script:focused=''; $script:foreignTarget=$false
    $script:report=@{offline=@{}}
    $script:root=New-DiaryNode 1 ([Windows.Automation.ControlType]::Window) ''
    $script:document=New-DiaryNode 2 ([Windows.Automation.ControlType]::Document) ''
    $script:button=New-DiaryNode 3 ([Windows.Automation.ControlType]::Button) $Name
    $script:root.Children=@($script:document); $script:document.Children=@($script:button)
    $script:walker=[pscustomobject]@{}
    $script:walker | Add-Member ScriptMethod GetFirstChild { param($Element) if ($Element.Children.Count) { return $Element.Children[0] }; return $null }
    $script:walker | Add-Member ScriptMethod GetNextSibling { param($Element) return $Element.Sibling }
}
foreach ($suffix in @('',' 0',' 1',' 12',' 999',' 1,000',' 12,345',' 1,234,567')) {
    Reset-Navigation ($diary+$suffix)
    Press-OfflineButton (Get-OfflineDiaryNavigationPattern)
    if ($focusCalls -ne 1 -or $invokes -ne 1 -or $guards -ne 6) { throw 'Legal diary count bypassed normal ownership/focus/invoke path' }
}
$badNames=[Collections.Generic.List[string]]::new()
foreach ($suffix in @(' suffix',' 1 extra','1',' 01',' -1',' 1.0',' 1e3',' 1,00',' 1234',' 1,0000','  1',"`n1"," 1`n",([regex]::Unescape('\u7247\u6bb5')),([string][char]0x00a0+'1'),' 1.000')) { $badNames.Add($diary+$suffix) }
$badNames.Add('prefix'+$diary)
foreach ($name in $badNames) {
    Reset-Navigation $name
    $found=Find-OfflineControl 'ControlType.Button' $pattern 0 -AllowAbsent
    if ($null -ne $found -or $focusCalls -ne 0 -or $invokes -ne 0) { throw 'Unsupported diary label matched navigation' }
}
foreach ($case in @('text_only','duplicate','other_matching_button','foreign_node','foreign_target')) {
    Reset-Navigation ($diary+' 1')
    switch ($case) {
        'text_only' { $button.Current.ControlType=[Windows.Automation.ControlType]::Text }
        'duplicate' { $button.Sibling=New-DiaryNode 4 ([Windows.Automation.ControlType]::Button) ($diary+' 1') }
        'other_matching_button' { $button.Sibling=New-DiaryNode 4 ([Windows.Automation.ControlType]::Button) $diary }
        'foreign_node' { $button.Current.ProcessId=99 }
        'foreign_target' { $script:foreignTarget=$true }
    }
    $caught=$null; $found=$null
    try { $found=Find-OfflineControl 'ControlType.Button' $pattern 0 -AllowAbsent } catch { $caught=$_.Exception.Message }
    $expected=switch ($case) { 'text_only' {$null} 'foreign_node' {'Offline UIA node escaped the bound process tree'} 'foreign_target' {'Foreign target'} default {'Offline selector is ambiguous'} }
    if ($null -ne $found -or $caught -cne $expected -or $focusCalls -ne 0 -or $invokes -ne 0) { throw 'Diary navigation weakened type, ownership or uniqueness' }
}
Write-Host 'PASS: bounded diary navigation count grammar and original guarded invoke path'
