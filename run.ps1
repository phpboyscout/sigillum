# Windows run of the plugin transport spike (plugin executables spec 0213, OQ12).
# Expects host.exe and notary-plugin.exe in the current directory.
$ErrorActionPreference = 'Continue'
$failures = @()
$host_exe = Join-Path $PWD 'host.exe'
$plugin_exe = Join-Path $PWD 'notary-plugin.exe'

function Report($name, $ok, $detail) {
    $verdict = if ($ok) { 'PASS' } else { 'FAIL' }
    Write-Output ("[{0}] {1}: {2}" -f $verdict, $name, $detail)
    if (-not $ok) { $script:failures += $name }
}

Write-Output ("host: {0}" -f $env:COMPUTERNAME)
Write-Output ("os: {0}" -f [System.Environment]::OSVersion.VersionString)
Write-Output ("powershell: {0}" -f $PSVersionTable.PSVersion)
Write-Output ("temp: {0}" -f $env:TEMP)

foreach ($t in 'unix', 'tcp', 'stdio') {
    Write-Output "== full run, transport $t"
    $out = & $host_exe -plugin $plugin_exe -transport $t 2>&1 | Out-String
    $code = $LASTEXITCODE
    Write-Output $out
    $ok = ($code -eq 0) -and ($out -match 'describe ok') -and ($out -match 'result ok') -and
          ($out -match 'cancel after first event') -and ($out -match 'wrong token refused') -and
          ($out -notmatch 'FAIL')
    if ($t -ne 'stdio') {
        $ok = $ok -and ($out -match 'plain gRPC client without token: rpc error')
    }
    Report "full-$t" $ok "exit $code"
}

Write-Output "== plugin run directly"
$msg = $null | & $plugin_exe 2>&1 | Out-String
$code = $LASTEXITCODE
Report 'direct-run-refused' (($code -eq 2) -and ($msg -match 'run it through sigillum')) ("exit {0}: {1}" -f $code, $msg.Trim())

Write-Output "== plugin with a transport but no token"
$env:SPIKE_PLUGIN_TRANSPORT = 'tcp'
$msg = $null | & $plugin_exe 2>&1 | Out-String
$code = $LASTEXITCODE
Remove-Item Env:SPIKE_PLUGIN_TRANSPORT
Report 'no-token-refused' (($code -eq 2) -and ($msg -match 'run it through sigillum')) ("exit {0}: {1}" -f $code, $msg.Trim())

foreach ($t in 'unix', 'tcp', 'stdio') {
    Write-Output "== host killed (taskkill /F), transport $t"
    $env:SPIKE_SLOW = '1'
    $h = Start-Process -FilePath $host_exe -ArgumentList '-plugin', "`"$plugin_exe`"", '-transport', $t -NoNewWindow -PassThru `
        -RedirectStandardOutput "killed-$t.out" -RedirectStandardError "killed-$t.err"
    Remove-Item Env:SPIKE_SLOW
    Start-Sleep -Milliseconds 1500
    $child = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($h.Id)" | Where-Object { $_.Name -eq 'notary-plugin.exe' }
    if (-not $child) {
        Report "killed-host-$t" $false 'no plugin child process found before the kill'
        Stop-Process -Id $h.Id -Force -ErrorAction SilentlyContinue
        continue
    }
    $childId = $child.ProcessId
    & taskkill.exe /F /PID $h.Id | Out-Null
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $gone = $false
    while ($sw.ElapsedMilliseconds -lt 5000) {
        if (-not (Get-Process -Id $childId -ErrorAction SilentlyContinue)) { $gone = $true; break }
        Start-Sleep -Milliseconds 100
    }
    $detail = if ($gone) { "plugin $childId exited $($sw.ElapsedMilliseconds) ms after the host was killed" } else { "plugin $childId still running 5 s after the host was killed" }
    Report "killed-host-$t" $gone $detail
    Get-Content "killed-$t.err" -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "  stderr: $_" }
    if (-not $gone) { Stop-Process -Id $childId -Force -ErrorAction SilentlyContinue }
}

Write-Output "== socket directories left behind in TEMP (informational)"
Get-ChildItem -Path $env:TEMP -Filter 'sigillum-plugin-*' -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Output ("  {0}" -f $_.FullName); Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }

Write-Output "== socket directory ACL during a run (informational: os.Chmod 0700 is a no-op on Windows)"
$env:SPIKE_SLOW = '1'
$h = Start-Process -FilePath $host_exe -ArgumentList '-plugin', "`"$plugin_exe`"", '-transport', 'unix' -NoNewWindow -PassThru `
    -RedirectStandardOutput acl.out -RedirectStandardError acl.err
Remove-Item Env:SPIKE_SLOW
Start-Sleep -Milliseconds 1500
Get-ChildItem -Path $env:TEMP -Filter 'sigillum-plugin-*' -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { (Get-Acl $_.FullName).Access | ForEach-Object { Write-Output ("  {0} {1} {2}" -f $_.IdentityReference, $_.AccessControlType, $_.FileSystemRights) } }
$h | Wait-Process -Timeout 20 -ErrorAction SilentlyContinue

if ($failures.Count -gt 0) {
    Write-Output ("FAILED: {0}" -f ($failures -join ', '))
    exit 1
}
Write-Output 'ALL PASS'
