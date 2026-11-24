<#
  Libera o acesso dos outros computadores ao servidor VIGIL (porta TCP 8443).
  Use pelo liberar_firewall.bat (botao direito > Executar como administrador).
#>
$ErrorActionPreference = 'Stop'
$port = 8443
$cfg = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'server\data\config.json'
if (Test-Path $cfg) { $c = Get-Content $cfg -Raw | ConvertFrom-Json; if ($c.port) { $port = [int]$c.port } }

Write-Host ''
Write-Host "  VIGIL - liberando a porta $port no Firewall do Windows" -ForegroundColor White
Write-Host ''

# 1) Regras de BLOQUEIO para python/pythonw vencem qualquer liberacao: remove as de entrada.
#    (o Windows cria essas regras quando o aviso "Permitir acesso?" e cancelado)
$blocks = Get-NetFirewallRule -Direction Inbound -Action Block -ErrorAction SilentlyContinue |
  Where-Object { ($_ | Get-NetFirewallApplicationFilter).Program -match 'python(w)?\.exe$' }
if ($blocks) {
  foreach ($r in $blocks) {
    $prog = ($r | Get-NetFirewallApplicationFilter).Program
    Write-Host "==> Removendo regra de bloqueio: $($r.DisplayName) ($prog)" -ForegroundColor Yellow
    Remove-NetFirewallRule -Name $r.Name
  }
} else {
  Write-Host '==> Nenhuma regra bloqueando o Python.' -ForegroundColor Cyan
}

# 2) Regra de entrada para a porta do VIGIL (todos os perfis de rede).
Get-NetFirewallRule -DisplayName "VIGIL $port" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "VIGIL $port" -Description 'Servidor central VIGIL (agentes e painel)' `
  -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any | Out-Null
Write-Host "==> Regra 'VIGIL $port' criada (entrada TCP $port liberada)." -ForegroundColor Green

# 3) Politica de dominio pode ignorar regras locais.
$gpo = Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { $_.Enabled -and $_.AllowLocalFirewallRules -eq 'False' }
if ($gpo) {
  Write-Host ''
  Write-Host "  ATENCAO: a politica do dominio ignora regras locais nos perfis: $($gpo.Name -join ', ')." -ForegroundColor Red
  Write-Host "  Peca ao responsavel pela rede/TI para liberar a entrada TCP $port para este computador."
}

Write-Host ''
Write-Host "  Pronto. Nos outros computadores, teste: https://$((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1).IPAddress):$port"
Write-Host ''
