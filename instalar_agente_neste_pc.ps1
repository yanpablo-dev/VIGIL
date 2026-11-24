<#
  Instala o VIGIL Agent NESTE computador (o mesmo que roda o servidor VIGIL).
  Use pelo instalar_agente_neste_pc.bat (botao direito > Executar como administrador).
  Servidor e impressao digital do certificado sao lidos automaticamente; so o token e pedido.
#>
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Crt = Join-Path $Root 'server\data\certs\vigil.crt'
$Cfg = Join-Path $Root 'server\data\config.json'
if (-not (Test-Path $Crt)) { throw 'Servidor VIGIL ainda nao foi iniciado neste computador (certificado nao encontrado).' }

$port = 8443
if (Test-Path $Cfg) { $c = Get-Content $Cfg -Raw | ConvertFrom-Json; if ($c.port) { $port = $c.port } }
$cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($Crt)
$fp = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)) -replace '-', '')
$server = "https://127.0.0.1:$port"

Write-Host ''
Write-Host '  Instalar o VIGIL Agent neste computador' -ForegroundColor White
Write-Host "  Servidor: $server"
Write-Host ''
Write-Host '  No painel do VIGIL, o token e a linha que comeca com vgl_ (no quadro amarelo).'
Write-Host '  Cole com o BOTAO DIREITO do mouse e tecle Enter.'
Write-Host ''
$token = ''
while ($token -notmatch '^vgl_[A-Za-z0-9_-]{30,64}$') {
  $token = (Read-Host '  Token').Trim()
  if ($token -notmatch '^vgl_[A-Za-z0-9_-]{30,64}$') { Write-Host '  Token invalido: deve comecar com vgl_. Tente de novo.' -ForegroundColor Yellow }
}

& (Join-Path $Root 'agent\windows\install.ps1') -Server $server -Token $token -Fingerprint $fp
