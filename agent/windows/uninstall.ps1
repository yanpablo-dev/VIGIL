<#
  VIGIL Agent - desinstalador para Windows (execute como Administrador)
    powershell -ExecutionPolicy Bypass -File "C:\Program Files\VIGIL Agent\uninstall.ps1" [-KeepConfig]
  -KeepConfig : mantem C:\ProgramData\VIGIL Agent (config, token e log).
  Dica: depois de desinstalar, revogue ou exclua o dispositivo no painel do VIGIL.
#>
param([switch]$KeepConfig)
$ErrorActionPreference = 'Continue'
$ServiceName = 'VIGILAgent'
$TaskName = 'VIGIL Agent'
$InstallDir = Join-Path $env:ProgramFiles 'VIGIL Agent'
$DataDir = Join-Path $env:ProgramData 'VIGIL Agent'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Execute como Administrador.'
}

if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
  Write-Host '==> Parando e removendo o servico' -ForegroundColor Cyan
  Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
  sc.exe delete $ServiceName | Out-Null
}
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Write-Host '==> Removendo a tarefa agendada' -ForegroundColor Cyan
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -like '*vigil_agent.py*' -or $_.Name -eq 'VIGIL-Agent.exe' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1

Write-Host '==> Removendo arquivos' -ForegroundColor Cyan
# o proprio script pode estar dentro de InstallDir: remove o restante e agenda a pasta
Get-ChildItem $InstallDir -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'uninstall.ps1' } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Start-Process cmd.exe -ArgumentList "/c timeout /t 2 >nul & rmdir /s /q `"$InstallDir`"" -WindowStyle Hidden
if (-not $KeepConfig) { Remove-Item $DataDir -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host 'VIGIL Agent desinstalado.' -ForegroundColor Green
Write-Host 'Lembre-se de revogar ou excluir este dispositivo no painel do VIGIL.'
