#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'ActSigner.Settings.psm1') -Force

function Assert-Settings {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw ('ASSERT: ' + $Message) }
}

$testRoot = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'ActSigner-Settings-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
try {
    $path = Join-Path $testRoot 'preferences/settings.json'
    $initial = Get-ActSignerSettings -Path $path
    Assert-Settings ($initial.SourceRoot -eq '') 'A new profile must not invent a source folder.'
    Assert-Settings ($initial.SaveBesideSources -eq $true) 'First launch must save beside each act.'

    Assert-Settings ($initial.SignatureNaming -ceq 'signer') 'New profiles must default to signer filenames.'

    $source = '\\VBOXSVR\Акты & архив\2026'
    $output = 'D:\Подписи пользователя\Отдельная папка'
    Assert-Settings (Save-ActSignerSettings -Path $path -SourceRoot $source -SeparateOutputRoot $output -SaveBesideSources $false) 'Initial settings save failed.'
    $loaded = Get-ActSignerSettings -Path $path
    Assert-Settings ($loaded.SourceRoot -ceq $source) 'Unicode or UNC source path did not round-trip.'
    Assert-Settings ($loaded.SeparateOutputRoot -ceq $output) 'Separate output path did not round-trip.'
    Assert-Settings ($loaded.SaveBesideSources -eq $false) 'Explicit separate-folder mode was lost.'

    $source = 'Y:\Тестовые документы\Акты&\Новая папка'
    Assert-Settings (Save-ActSignerSettings -Path $path -SourceRoot $source -SeparateOutputRoot $output -SaveBesideSources $true) 'Atomic replacement failed.'
    $loaded = Get-ActSignerSettings -Path $path
    Assert-Settings ($loaded.SourceRoot -ceq $source) 'Last chosen folder was not replaced.'
    Assert-Settings ($loaded.SeparateOutputRoot -ceq $output) 'Beside mode erased the separate output preference.'
    Assert-Settings ($loaded.SaveBesideSources -eq $true) 'Explicit beside mode was lost.'
    $raw = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path))
    Assert-Settings ((@($raw.PSObject.Properties.Name | Sort-Object) -join ',') -ceq 'SaveBesideSources,SeparateOutputRoot,SignatureNaming,SourceRoot') 'Settings contain unexpected data.'
    $bytes = [IO.File]::ReadAllBytes($path)
    Assert-Settings ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) 'Settings encoding is not UTF-8 with BOM.'
    Assert-Settings (@(Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($path)) -Filter '*.tmp' -Force).Count -eq 0) 'A staging file remained after saving.'

    [IO.File]::WriteAllText($path, '{broken json')
    $loaded = Get-ActSignerSettings -Path $path
    Assert-Settings ($loaded.SourceRoot -eq '' -and $loaded.SaveBesideSources) 'Damaged preferences should fall back without throwing.'
    [IO.File]::WriteAllText($path, '{"SourceRoot":123,"SeparateOutputRoot":[],"SaveBesideSources":"false","PIN":"must-not-be-read"}')
    $loaded = Get-ActSignerSettings -Path $path
    Assert-Settings ($loaded.SourceRoot -eq '' -and $loaded.SeparateOutputRoot -eq '' -and $loaded.SaveBesideSources) 'Wrong JSON types were coerced into settings.'
    [IO.File]::WriteAllText($path, '[{"SourceRoot":"wrong","SaveBesideSources":false}]')
    $loaded = Get-ActSignerSettings -Path $path
    Assert-Settings ($loaded.SourceRoot -eq '' -and $loaded.SaveBesideSources) 'An array was accepted as settings.'

    $blockedParent = Join-Path $testRoot 'not-a-folder'
    [IO.File]::WriteAllText($blockedParent, 'unchanged')
    $saved = Save-ActSignerSettings -Path (Join-Path $blockedParent 'settings.json') -SourceRoot $source
    Assert-Settings (-not $saved) 'A save failure must return false.'
    Assert-Settings ([IO.File]::ReadAllText($blockedParent) -ceq 'unchanged') 'Failed save modified an existing file.'

    $occupiedDestination = Join-Path $testRoot 'blocked/settings.json'
    [void][IO.Directory]::CreateDirectory($occupiedDestination)
    $keep = Join-Path $occupiedDestination 'keep.txt'
    [IO.File]::WriteAllText($keep, 'unchanged')
    $saved = Save-ActSignerSettings -Path $occupiedDestination -SourceRoot $source
    Assert-Settings (-not $saved) 'Occupied destination should not be replaced.'
    Assert-Settings ([IO.File]::ReadAllText($keep) -ceq 'unchanged') 'Occupied destination contents were changed.'
    Assert-Settings (@(Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($occupiedDestination)) -Filter '*.tmp' -Force).Count -eq 0) 'Failed atomic publication left a staging file.'
    foreach($mode in @('signer','document_signer','legacy')) {
        Assert-Settings (Save-ActSignerSettings -Path $path -SourceRoot $source -SeparateOutputRoot $output -SaveBesideSources $true -SignatureNaming $mode) 'Naming preference save failed.'
        $loaded=Get-ActSignerSettings -Path $path
        Assert-Settings ($loaded.SignatureNaming -ceq $mode -and $loaded.SourceRoot -ceq $source -and $loaded.SaveBesideSources) 'Naming preference damaged folder/mode settings.'
    }
    [IO.File]::WriteAllText($path,'{"SignatureNaming":"invalid","SourceRoot":"C:\\Synthetic"}')
    Assert-Settings ((Get-ActSignerSettings -Path $path).SignatureNaming -ceq 'signer') 'Invalid naming mode must use the safe default.'
    Write-Host 'ActSigner.Settings tests passed.'
}
finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
