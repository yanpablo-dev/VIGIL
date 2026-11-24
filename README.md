# VIGIL — Monitoramento distribuído de infraestrutura

Central única que recebe métricas de vários computadores **Windows e Linux**, inclusive em redes diferentes.
Cada computador roda o **VIGIL Agent**, que só faz conexões **de saída** (HTTPS) para o servidor — nada é aberto
nos computadores monitorados, e o agente **não** executa comandos nem oferece acesso remoto à tela.

```
 PC Windows  ─┐                         ┌──────────────────────────────┐
 Servidor Linux ─┼── HTTPS (saída) ──▶ │ VIGIL Server (porta 8443)    │ ◀── Painel web (administradores)
 Filial (NAT)─┘   token por agente      │API agentes · alertas · SQLite│
                                        └──────────────────────────────┘
```

## Estrutura

| Pasta / arquivo | Conteúdo |
|---|---|
| `server/vigil_server.py` | Servidor central: painel, API dos agentes, alertas, TLS, banco SQLite |
| `server/web/` | Painel (HTML/CSS/JS, sem dependências externas) |
| `server/data/` | Criada na 1ª execução: `config.json`, `vigil.db`, `certs/`, `vigil.log` |
| `agent/vigil_agent.py` | Agente (Windows e Linux) — coleta e envio |
| `agent/windows/` | `install.ps1`, `uninstall.ps1`, `vigil_service.py` (serviço), `build_exe.ps1` |
| `agent/linux/` | `install.sh`, `uninstall.sh`, unidade systemd de referência |
| `iniciar_vigil.bat` | Inicia o servidor neste computador |

## 1. Instalar o servidor central

Requisitos: Python 3.9+ e o pacote `cryptography` (só para gerar o certificado na 1ª vez):
`pip install -r server/requirements.txt`. O agente usa `agent/requirements.txt` (os instaladores já cuidam disso).

1. Dê dois cliques em `iniciar_vigil.bat` (ou `python server\vigil_server.py`).
2. Abra **neste computador** `https://localhost:8443` e crie o administrador (a configuração inicial só é aceita via localhost).
   O certificado é autoassinado: o navegador mostra um aviso na primeira vez — confira a impressão digital exibida no console.
3. **Firewall do Windows do servidor**: libere a entrada TCP **8443** para o `python.exe`
   (atenção a regras "python.exe — Bloquear" criadas automaticamente, que causam *timeout* nos outros computadores).

```powershell
New-NetFirewallRule -DisplayName "VIGIL 8443" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

Para rodar o servidor sempre ligado, crie uma Tarefa Agendada "Ao iniciar o sistema" executando `iniciar_vigil.bat`.

### Configuração (`server/data/config.json`)

| Chave | Padrão | Função |
|---|---|---|
| `port` | 8443 | Porta HTTPS |
| `tls` | true | Mantenha ativo. `false` só com `host: 127.0.0.1` atrás de um proxy HTTPS |
| `cert_file` / `key_file` | vazio | Certificado próprio (ex.: Let's Encrypt). Vazio = autoassinado |
| `trust_proxy_headers` | false | `true` apenas atrás de proxy confiável (Cloudflare Tunnel) para ver o IP real |
| `offline_after_seconds` | 90 | Sem comunicação por esse tempo (mín. 3 intervalos) ⇒ offline + alerta |
| `default_interval_seconds` | 30 | Intervalo de envio dos agentes (ajustável por dispositivo no painel) |
| `token_rotation_days` | 30 | Rotação automática e transparente dos tokens |
| `enrollment_valid_days` | 7 | Validade do token de cadastro até o 1º acesso |
| `retention_days` | 7 | Retenção do histórico de métricas |

## 2. Adicionar um computador

1. Painel → **Adicionar dispositivo** → nome, sistema, IP, grupo, localização, descrição.
2. O VIGIL gera um **token individual** (exibido uma única vez) e o comando de instalação pronto para Windows e Linux.
3. Execute o comando no computador a ser monitorado:
   * **Windows** — PowerShell **como Administrador**. Baixa o agente (validando a impressão digital do certificado),
     instala `psutil`/`pywin32`, grava `C:\ProgramData\VIGIL Agent\config.json` (acesso só SYSTEM/Administradores),
     testa a autenticação e cria o **Serviço do Windows "VIGIL Agent"** (início automático, reinício em falha).
     Sem Python na máquina: o instalador tenta o `winget`; alternativa: gere `VIGIL-Agent.exe` com `build_exe.ps1`.
   * **Linux** — terminal com `sudo`. Cria o usuário de sistema `vigil-agent`, instala em `/opt/vigil-agent`
     (venv com psutil), grava `/var/lib/vigil-agent/config.json` (0600) e habilita o serviço **systemd** `vigil-agent`.
4. O agente se autentica e o computador aparece **Online** no dashboard (o modal acompanha a conexão ao vivo).

Sem acesso de rede ao servidor durante a instalação? Baixe o pacote `.zip` no próprio modal, copie para o
computador e rode o instalador com os mesmos parâmetros (`-Server`, `-Token`, `-Fingerprint`).

### Desinstalar

* Windows: `powershell -ExecutionPolicy Bypass -File "C:\Program Files\VIGIL Agent\uninstall.ps1"` (`-KeepConfig` mantém o token)
* Linux: `sudo bash /opt/vigil-agent/uninstall.sh` (`--keep-config` mantém o token)

Depois, **revogue ou exclua** o dispositivo no painel.

## 3. Computadores em outras redes (filiais, home office, nuvem)

A comunicação é sempre **iniciada pelo agente**, então o computador monitorado pode estar atrás de NAT/firewall sem
nenhuma porta aberta. Só o **servidor** precisa ser alcançável:

* **Encaminhamento de porta** no roteador do servidor (TCP 8443 → IP do servidor). Em Configurações, defina o
  *Endereço público* como `https://SEU-IP-PUBLICO:8443`. O certificado autoassinado continua protegido por pinning.
* **Cloudflare Tunnel / proxy HTTPS** com domínio próprio: defina o *Endereço público* como `https://vigil.suaempresa.com.br`.
  Com nome de domínio, os agentes validam o certificado pela CA normal (sem pinning). Ative `trust_proxy_headers`.

## 4. Segurança

* **TLS 1.2+** em tudo. Certificado autoassinado ⇒ o agente fixa a impressão digital SHA-256 (*pinning*) e
  **aborta antes de enviar o token** se o certificado não conferir; o `curl` do Linux usa `--pinnedpubkey`.
* **Token individual por dispositivo** (256 bits), guardado no servidor apenas como hash SHA-256.
  * *Rotacionar*: o agente recebe o token novo na próxima comunicação e o antigo é invalidado quando o novo é usado (sem reinstalar). Automático a cada `token_rotation_days`.
  * *Revogar*: bloqueio imediato; tentativas seguintes ficam registradas.
  * *Reemitir*: novo token de cadastro (reinstalação ou reativação).
* **Proteção contra agentes não autorizados**: token desconhecido/revogado/expirado ⇒ 401 e registro; 10 falhas em 10 min bloqueiam o IP por 15 min.
* **Rate limiting** por dispositivo, por IP, no login e nos downloads.
* **Validação** de todo dado recebido (tipos, faixas, tamanhos, limite de 512 KB por requisição, amostras de até 24 h).
* **Painel**: senhas PBKDF2 (240 mil iterações), cookie `HttpOnly`/`Secure`/`SameSite=Strict`, token CSRF,
  CSP sem scripts inline, perfis **Administrador / Operador / Somente leitura**.
* **Registro de conexões**: primeira conexão, reconexões, desconexões, falhas de autenticação, rotações, logins.
* **Multi-organização**: todos os dados carregam `org_id` e todas as consultas filtram pela organização do usuário — base para evoluir a SaaS.
* O agente no Linux roda como usuário sem privilégios com systemd endurecido (`ProtectSystem=strict`, `NoNewPrivileges`...).

## 5. Alertas

Por dispositivo, com limites padrão da organização (Configurações) e limites próprios por computador:

| Alerta | Padrão |
|---|---|
| Computador offline | sem comunicação > 90 s (3 intervalos) |
| Agente parou de enviar métricas | responde, mas sem métricas há > 4 intervalos |
| CPU | atenção 75% · crítico 90% (2 leituras seguidas) |
| RAM | atenção 75% · crítico 85% |
| Disco (volume mais cheio) | atenção 80% · crítico 90% |
| Temperatura (quando o hardware informa) | atenção 75 °C · crítico 85 °C |

Alertas fecham sozinhos quando o valor normaliza (histerese de 2 pontos) e podem ser marcados como "ciente".

## 6. Escala

Os agentes se cadastram sozinhos pelo painel — dezenas ou centenas de dispositivos não exigem mudar código.
O servidor usa threads por conexão e SQLite em WAL; com intervalo de 30 s, 300 agentes geram ~10 req/s.
Para milhares de agentes, troque o SQLite por PostgreSQL mantendo a mesma API.

## API dos agentes

| Método | Rota | Uso |
|---|---|---|
| POST | `/agent/v1/hello` | Identificação (hostname, SO, IPs, CPU, RAM) — na conexão e a cada reconexão |
| POST | `/agent/v1/report` | Heartbeat + lote de amostras (até 120; o agente acumula ~2 h durante quedas) |

Cabeçalho `Authorization: Bearer vgl_…`. Resposta: `{interval, new_token?}` — nunca comandos.

## Créditos

Desenvolvido por Yan Pablo, com a ajuda de Guilherme.

## Licença

Distribuído sob a licença MIT. Veja o arquivo [LICENSE](LICENSE).
