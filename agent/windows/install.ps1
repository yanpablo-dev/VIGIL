<#
  VIGIL Agent - instalador para Windows
  Execute em um PowerShell aberto como ADMINISTRADOR:

    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Server https://SERVIDOR:8443 -Token vgl_xxx -Fingerprint ABCD...

  -Fingerprint : impressao digital SHA-256 do certificado do servidor (quando autoassinado; aparece no painel).
  -Interval    : segundos entre envios (padrao 30; o servidor pode ajustar).
  -Python      : caminho do python.exe (opcional; detectado automaticamente).
  -NoService   : usa Tarefa Agendada em vez de Servico do Windows.

  Se existir VIGIL-Agent.exe (gerado por build_exe.ps1) nesta pasta, o Python nao e necessario.
#>
param(
  [Parameter(Mandatory = $true)][string]$Server,
  [Parameter(Mandatory = $true)][string]$Token,
  [string]$Fingerprint = "",
  [int]$Interval = 30,
  [string]$Python = "",
  [switch]$NoService
)
$ErrorActionPreference = 'Stop'
$ServiceName = 'VIGILAgent'
$TaskName = 'VIGIL Agent'
$InstallDir = Join-Path $env:ProgramFiles 'VIGIL Agent'
$DataDir = Join-Path $env:ProgramData 'VIGIL Agent'
$Config = Join-Path $DataDir 'config.json'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m) { Write-Host "    $m" -ForegroundColor Green }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Execute este instalador em um PowerShell aberto como Administrador.'
}
if ($Token -notmatch '^vgl_[A-Za-z0-9_-]{30,64}$') { throw 'Token invalido (deve comecar com vgl_).' }
if ($Server -notmatch '^https://') { throw 'O endereco do servidor deve comecar com https://' }

Write-Host ''
Write-Host '  VIGIL Agent - instalacao' -ForegroundColor White
Write-Host "  Servidor: $Server"
Write-Host ''

# ---------------------------------------------------------------- executor (exe ou python)
$ExeSrc = Join-Path $Here 'VIGIL-Agent.exe'
$UseExe = Test-Path $ExeSrc
$Py = $null

function Find-Python {
  if ($Python) { return $Python }
  foreach ($c in @('py', 'python', 'python3')) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike '*WindowsApps*') {
      try {
        if ($c -eq 'py') { $exe = & $cmd.Source -3 -c 'import sys;print(sys.executable)' } else { $exe = & $cmd.Source -c 'import sys;print(sys.executable)' }
        if ($LASTEXITCODE -eq 0 -and $exe) { return ($exe | Select-Object -First 1).Trim() }
      } catch {}
    }
  }
  $globs = @("$env:ProgramFiles\Python3*\python.exe", "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe",
             "$env:LOCALAPPDATA\Python\pythoncore-3*\python.exe")
  $cands = Get-ChildItem $globs -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
  if ($cands) { return $cands[0].FullName }
  return $null
}

if (-not $UseExe) {
  Step 'Localizando o Python'
  $Py = Find-Python
  if (-not $Py) {
    $wg = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $wg) { throw 'Python 3 nao encontrado. Instale o Python 3.9+ (python.org, opcao "for all users") ou use o VIGIL-Agent.exe.' }
    Step 'Python nao encontrado: instalando Python 3.12 via winget (todos os usuarios)'
    & $wg.Source install --id Python.Python.3.12 --scope machine --silent --accept-package-agreements --accept-source-agreements | Out-Host
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
    $Py = Find-Python
    if (-not $Py) { throw 'Nao foi possivel instalar o Python automaticamente.' }
  }
  # sem aspas duplas: o PowerShell 5.1 as remove ao repassar argumentos para programas externos
  $ver = (& $Py -c 'import sys;print(str(sys.version_info[0])+chr(46)+str(sys.version_info[1]))' | Select-Object -First 1).Trim()
  Ok "Python $ver em $Py"
  if ([version]$ver -lt [version]'3.8') { throw 'E necessario Python 3.8 ou superior.' }

  Step 'Instalando dependencias (psutil, pywin32)'
  & $Py -m pip install --upgrade --disable-pip-version-check --quiet psutil pywin32 | Out-Host
  if ($LASTEXITCODE -ne 0) { throw 'Falha ao instalar psutil/pywin32 com pip (verifique o acesso a internet).' }
}

# ---------------------------------------------------------------- remove instalacao anterior
$old = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($old) {
  Step 'Removendo servico anterior'
  Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
  sc.exe delete $ServiceName | Out-Null
  Start-Sleep -Seconds 2
}
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# ---------------------------------------------------------------- arquivos
Step "Copiando arquivos para $InstallDir"
New-Item -ItemType Directory -Force $InstallDir, $DataDir | Out-Null
if ($UseExe) {
  Copy-Item $ExeSrc $InstallDir -Force
  $Runner = Join-Path $InstallDir 'VIGIL-Agent.exe'
  $RunnerArgs = @()
} else {
  foreach ($f in 'vigil_agent.py', 'vigil_service.py') {
    $src = Join-Path $Here $f
    if (-not (Test-Path $src)) { $src = Join-Path (Split-Path $Here) $f }  # estrutura da pasta VIGIL (agent\vigil_agent.py)
    if (-not (Test-Path $src)) { throw "Arquivo $f nao encontrado ao lado do instalador." }
    Copy-Item $src $InstallDir -Force
  }
  $Runner = $Py
  $RunnerArgs = @((Join-Path $InstallDir 'vigil_service.py'))
}
foreach ($f in 'uninstall.ps1') { $src = Join-Path $Here $f; if (Test-Path $src) { Copy-Item $src $InstallDir -Force } }

function Invoke-Agent([string[]]$a) {
  $all = $RunnerArgs + $a
  & $Runner @all | Out-Host
  return $LASTEXITCODE
}

# ---------------------------------------------------------------- configuracao (protegida)
Step 'Gravando configuracao (servidor e token)'
$cfgArgs = @('--config', $Config, 'configure', '--server', $Server, '--token', $Token, '--interval', "$Interval")
if ($Fingerprint) { $cfgArgs += @('--fingerprint', $Fingerprint) }
if ((Invoke-Agent $cfgArgs) -ne 0) { throw 'Falha ao gravar a configuracao.' }
# somente SYSTEM e Administradores leem o token
icacls $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
Ok "Configuracao em $Config (acesso restrito a SYSTEM/Administradores)"

Step 'Testando autenticacao com o servidor'
if ((Invoke-Agent @('--config', $Config, 'test')) -ne 0) {
  throw 'O agente nao conseguiu se autenticar. Confira endereco, token (validade), impressao digital e o firewall do SERVIDOR (porta liberada).'
}

# ---------------------------------------------------------------- servico / tarefa
$mode = ''
if (-not $NoService) {
  Step 'Registrando o Servico do Windows "VIGIL Agent" (inicio automatico)'
  try {
    if ((Invoke-Agent @('--startup', 'auto', 'install')) -ne 0) { throw 'falha ao registrar o servico' }
    sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/60000 | Out-Null
    Start-Service $ServiceName
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Service $ServiceName).Status -ne 'Running' -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    if ((Get-Service $ServiceName).Status -eq 'Running') { $mode = 'service'; Ok 'Servico em execucao.' }
    else { throw 'servico nao entrou em execucao' }
  } catch {
    Write-Warning "Nao foi possivel usar o servico ($($_.Exception.Message)). Usando Tarefa Agendada."
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
  }
}
if (-not $mode) {
  Step 'Registrando Tarefa Agendada "VIGIL Agent" (SYSTEM, ao iniciar o Windows)'
  if ($UseExe) { $exe = $Runner; $arg = "--config `"$Config`" run" }
  else {
    $exe = Join-Path (Split-Path $Py) 'pythonw.exe'; if (-not (Test-Path $exe)) { $exe = $Py }
    $arg = "`"$(Join-Path $InstallDir 'vigil_agent.py')`" --config `"$Config`" run"
  }
  $action = New-ScheduledTaskAction -Execute $exe -Argument $arg -WorkingDirectory $InstallDir
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $tp = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $set = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $tp -Settings $set -Force | Out-Null
  Start-ScheduledTask -TaskName $TaskName
  $mode = 'task'
  Ok 'Tarefa agendada criada e iniciada.'
}

@{ mode = $mode; python = $Py; exe = $UseExe; installed_at = (Get-Date).ToString('s'); server = $Server } |
  ConvertTo-Json | Out-File -Encoding utf8 (Join-Path $DataDir 'install.json')

Write-Host ''
Write-Host '  VIGIL Agent instalado com sucesso!' -ForegroundColor Green
Write-Host '  O computador ja deve aparecer como Online no painel do VIGIL.'
Write-Host "  Log do agente: $DataDir\agent.log"
Write-Host "  Desinstalar:  powershell -ExecutionPolicy Bypass -File `"$InstallDir\uninstall.ps1`""
Write-Host ''
