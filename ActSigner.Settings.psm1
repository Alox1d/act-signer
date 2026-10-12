# User-specific folder preferences for Windows PowerShell 5.1.
# No certificate, private-key or PIN data belongs in this file.
Set-StrictMode -Version 2.0

function Get-ActSignerSettingsPath {
    $localData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if ([string]::IsNullOrWhiteSpace($localData)) {
        throw 'Не удалось определить папку настроек текущего пользователя.'
    }
    return [IO.Path]::Combine($localData, 'ActSigner', 'settings.json')
}

function Get-ActSignerSettings {
    [CmdletBinding()]
    param([string]$Path)

    $settings = [pscustomobject]@{
        SourceRoot = ''
        SeparateOutputRoot = ''
        SaveBesideSources = $true
    }
    try {
        if ([string]::IsNullOrWhiteSpace($Path)) { $Path = Get-ActSignerSettingsPath }
        if (-not [IO.File]::Exists($Path)) { return $settings }
        $file = New-Object IO.FileInfo($Path)
        if ($file.Length -gt 64KB) { return $settings }
        $json = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
        if (-not $json.TrimStart().StartsWith('{')) { return $settings }
        $loaded = ConvertFrom-Json -InputObject $json -ErrorAction Stop
        if ($null -eq $loaded -or $loaded -is [array]) { return $settings }

        # Keep disconnected VM shares and removable paths: their absence now
        # must not erase the folder the user chose last time.
        foreach ($name in @('SourceRoot', 'SeparateOutputRoot')) {
            $property = $loaded.PSObject.Properties[$name]
            if ($null -ne $property -and $property.Value -is [string] -and $property.Value.Length -le 32767) {
                $settings.$name = $property.Value.Trim()
            }
        }
        $mode = $loaded.PSObject.Properties['SaveBesideSources']
        if ($null -ne $mode -and $mode.Value -is [bool]) {
            $settings.SaveBesideSources = $mode.Value
        }
    }
    catch {
        # Missing, damaged or inaccessible preferences never block the app.
        Write-Verbose ('Не удалось прочитать настройки папок: ' + $_.Exception.Message)
    }
    return $settings
}

function Save-ActSignerSettings {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$SourceRoot = '',
        [AllowEmptyString()][string]$SeparateOutputRoot = '',
        [bool]$SaveBesideSources = $true,
        [string]$Path
    )

    $temporaryPath = $null
    $stream = $null
    $writer = $null
    try {
        if ([string]::IsNullOrWhiteSpace($Path)) { $Path = Get-ActSignerSettingsPath }
        $Path = [IO.Path]::GetFullPath($Path)
        $directory = [IO.Path]::GetDirectoryName($Path)
        [void][IO.Directory]::CreateDirectory($directory)
        $settings = [ordered]@{
            SourceRoot = ([string]$SourceRoot).Trim()
            SeparateOutputRoot = ([string]$SeparateOutputRoot).Trim()
            SaveBesideSources = $SaveBesideSources
        }
        $json = ConvertTo-Json -InputObject $settings -Depth 2
        $temporaryPath = [IO.Path]::Combine($directory, '.settings-' + [guid]::NewGuid().ToString('N') + '.tmp')
        $stream = [IO.File]::Open($temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $writer = New-Object IO.StreamWriter($stream, (New-Object Text.UTF8Encoding($true)))
        $writer.Write($json)
        $writer.Flush()
        $stream.Flush($true)
        $writer.Dispose()
        $writer = $null
        $stream = $null

        # Same-directory replacement is atomic. Never delete the old settings
        # or fall back to writing over them if the replacement fails.
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporaryPath, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temporaryPath, $Path) }
        $temporaryPath = $null
        return $true
    }
    catch {
        Write-Verbose ('Не удалось сохранить настройки папок: ' + $_.Exception.Message)
        return $false
    }
    finally {
        if ($null -ne $writer) { try { $writer.Dispose() } catch { } }
        elseif ($null -ne $stream) { try { $stream.Dispose() } catch { } }
        if ($null -ne $temporaryPath -and [IO.File]::Exists($temporaryPath)) {
            try { [IO.File]::Delete($temporaryPath) } catch { }
        }
    }
}

Export-ModuleMember -Function Get-ActSignerSettings, Save-ActSignerSettings
