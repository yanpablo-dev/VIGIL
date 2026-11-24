#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VIGIL Agent - coleta metricas deste computador e envia ao servidor VIGIL central.

Principios:
  * Somente conexoes de SAIDA (HTTPS). Nao abre portas, funciona atras de NAT/firewall.
  * Nao executa comandos recebidos do servidor e nao oferece acesso remoto. O servidor so
    devolve configuracao (intervalo) e, quando solicitado, um token novo (rotacao).
  * Certificado do servidor validado pela CA do sistema OU por impressao digital fixada (pinning).

Uso:
  vigil_agent.py configure --server https://SERVIDOR:8443 --token vgl_... [--fingerprint HEX]
  vigil_agent.py test        # testa autenticacao e envio uma vez
  vigil_agent.py collect     # mostra as metricas coletadas (sem rede)
  vigil_agent.py run         # execucao continua (usada pelo servico)
"""
import argparse
import collections
import hashlib
import hmac
import http.client
import json
import logging
import logging.handlers
import os
import platform
import random
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlparse

try:
    import psutil
except ImportError:  # pragma: no cover
    sys.stderr.write("O VIGIL Agent precisa do pacote 'psutil' (pip install psutil).\n")
    raise

AGENT_VERSION = "1.0.0"
log = logging.getLogger("vigil-agent")


# --------------------------------------------------------------------------- configuracao

def default_config_path():
    if os.name == "nt":
        return os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "VIGIL Agent", "config.json")
    return "/var/lib/vigil-agent/config.json"


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    for k in ("server_url", "token"):
        if not cfg.get(k):
            raise ValueError(f"Configuração incompleta: '{k}' ausente em {path}")
    return cfg


def save_config(path, cfg):
    """Gravacao atomica (evita config corrompida se faltar energia durante a rotacao de token)."""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def setup_logging(cfg_path, verbose=False):
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    if not log.handlers:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        log.addHandler(sh)
        try:
            lp = os.path.join(os.path.dirname(cfg_path), "agent.log")
            fh = logging.handlers.RotatingFileHandler(lp, maxBytes=2_000_000, backupCount=2, encoding="utf-8")
            fh.setFormatter(fmt)
            log.addHandler(fh)
        except OSError:
            pass


# --------------------------------------------------------------------------- coleta

SKIP_FS = {"squashfs", "tmpfs", "devtmpfs", "overlay", "iso9660", "udf", "proc", "sysfs", "cgroup", "cgroup2", ""}


class Collector:
    def __init__(self):
        self.procs = {}
        self.ncpu = psutil.cpu_count() or 1
        psutil.cpu_percent(None)
        psutil.cpu_percent(None, percpu=True)
        self.last_net = (time.monotonic(), psutil.net_io_counters(pernic=True))
        self._temp_cache = (0, None, [])
        self._prime_processes()

    def _prime_processes(self):
        for p in psutil.process_iter():
            try:
                p.cpu_percent(None)
                self.procs[p.pid] = p
            except (psutil.Error, OSError):
                pass

    @staticmethod
    def primary_ip(server_host=None):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((server_host or "8.8.8.8", 80))  # UDP "connect" nao envia pacotes
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return ""

    @staticmethod
    def all_ips():
        out = []
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6) and not a.address.startswith(("127.", "::1", "fe80")):
                    out.append(a.address.split("%")[0])
        return out[:16]

    @staticmethod
    def os_info():
        info = {"system": platform.system(), "release": platform.release(), "version": platform.version(),
                "arch": platform.machine(), "pretty": ""}
        if info["system"] == "Linux":
            try:
                with open("/etc/os-release", encoding="utf-8") as f:
                    kv = dict(l.strip().split("=", 1) for l in f if "=" in l)
                info["pretty"] = kv.get("PRETTY_NAME", "").strip('"')
            except OSError:
                pass
        elif info["system"] == "Windows":
            try:
                ver = sys.getwindowsversion()
                edition = platform.win32_edition() or ""
                name = "Windows 11" if ver.build >= 22000 else f"Windows {platform.release()}"
                if "Server" in edition or "Server" in platform.release():
                    name = f"Windows Server {platform.release()}"
                info["pretty"] = f"{name} {edition} (build {ver.build})".replace("  ", " ")
            except Exception:
                pass
        return info

    def system_info(self, server_host=None):
        cpu_model = platform.processor()
        if platform.system() == "Linux":
            try:
                with open("/proc/cpuinfo", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("model name"):
                            cpu_model = line.split(":", 1)[1].strip()
                            break
            except OSError:
                pass
        return {
            "agent_version": AGENT_VERSION,
            "hostname": socket.gethostname(),
            "os": self.os_info(),
            "ips": self.all_ips(),
            "primary_ip": self.primary_ip(server_host),
            "boot_time": psutil.boot_time(),
            "cpu_model": cpu_model,
            "cpu_count": psutil.cpu_count(logical=False) or self.ncpu,
            "cpu_threads": self.ncpu,
            "ram_total": psutil.virtual_memory().total,
        }

    def temperatures(self):
        """Temperatura quando o hardware/SO expoe. Cache de 60 s (consulta pode ser lenta)."""
        t0, top, lst = self._temp_cache
        if time.monotonic() - t0 < 60:
            return top, lst
        lst = []
        try:
            if hasattr(psutil, "sensors_temperatures"):
                for chip, entries in (psutil.sensors_temperatures() or {}).items():
                    for e in entries:
                        if e.current and 0 < e.current < 150:
                            lst.append({"label": f"{chip} {e.label}".strip(), "c": round(e.current, 1)})
            elif os.name == "nt":
                lst = self._windows_temps()
        except Exception as e:  # sensores sao opcionais
            log.debug("Temperatura indisponível: %s", e)
        top = max((x["c"] for x in lst), default=None)
        self._temp_cache = (time.monotonic(), top, lst[:32])
        return top, lst[:32]

    @staticmethod
    def _windows_temps():
        try:
            import pythoncom  # pywin32
            import win32com.client
        except ImportError:
            return []
        # COM fica inicializado na thread do agente (sem CoUninitialize: evita liberar objetos ainda vivos)
        pythoncom.CoInitialize()
        out = []
        try:
            wmi = win32com.client.GetObject(r"winmgmts:\\.\root\wmi")
            for z in wmi.ExecQuery("SELECT InstanceName, CurrentTemperature FROM MSAcpi_ThermalZoneTemperature"):
                c = z.CurrentTemperature / 10.0 - 273.15
                if 0 < c < 150:
                    out.append({"label": str(z.InstanceName).split("\\")[-1][:60], "c": round(c, 1)})
        except Exception:
            pass  # exige privilegios (o servico roda como SYSTEM) e suporte do firmware
        return out

    def processes(self, top_n=15):
        rows, seen = [], set()
        for p in psutil.process_iter(["pid", "name", "memory_info", "memory_percent"]):
            seen.add(p.pid)
            try:
                proc = self.procs.get(p.pid)
                if proc is None:
                    proc = p
                    proc.cpu_percent(None)
                    self.procs[p.pid] = proc
                    cpu = 0.0
                else:
                    cpu = proc.cpu_percent(None) / self.ncpu
                mi = p.info.get("memory_info")
                rows.append({"pid": p.pid, "name": (p.info.get("name") or "?")[:80], "cpu": round(cpu, 1),
                             "mem": round(p.info.get("memory_percent") or 0, 1),
                             "mem_mb": round(mi.rss / 1048576, 1) if mi else 0})
            except (psutil.Error, OSError):
                continue
        for pid in list(self.procs):
            if pid not in seen:
                del self.procs[pid]
        rows = [r for r in rows if r["pid"] != 0 and r["name"] not in ("System Idle Process", "Idle")]
        by_cpu = sorted(rows, key=lambda r: r["cpu"], reverse=True)[:top_n]
        by_mem = sorted(rows, key=lambda r: r["mem"], reverse=True)[:top_n]
        merged = {r["pid"]: r for r in by_cpu + by_mem}
        return sorted(merged.values(), key=lambda r: (r["cpu"], r["mem"]), reverse=True)[:top_n * 2], len(rows)

    def sample(self):
        vm, sw = psutil.virtual_memory(), psutil.swap_memory()
        disks = []
        for part in psutil.disk_partitions(all=False):
            if part.fstype.lower() in SKIP_FS or "cdrom" in part.opts or part.mountpoint.startswith(("/snap", "/boot/efi")):
                continue
            try:
                u = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                continue
            if u.total < 512 * 1024 * 1024:
                continue
            disks.append({"mount": part.mountpoint, "fs": part.fstype, "total": u.total, "used": u.used,
                          "pct": round(u.percent, 1)})
        t, cur = time.monotonic(), psutil.net_io_counters(pernic=True)
        t0, prev = self.last_net
        dt = max(t - t0, 0.001)
        self.last_net = (t, cur)
        rx = tx = rx_tot = tx_tot = 0.0
        ifaces = []
        addrs = psutil.net_if_addrs()
        for name, c in cur.items():
            low = name.lower()
            if low == "lo" or "loopback" in low:
                continue
            p = prev.get(name)
            irx = max(0, c.bytes_recv - p.bytes_recv) / dt if p else 0
            itx = max(0, c.bytes_sent - p.bytes_sent) / dt if p else 0
            rx, tx, rx_tot, tx_tot = rx + irx, tx + itx, rx_tot + c.bytes_recv, tx_tot + c.bytes_sent
            ips = [a.address.split("%")[0] for a in addrs.get(name, []) if a.family in (socket.AF_INET, socket.AF_INET6)]
            if ips or irx or itx:
                ifaces.append({"name": name[:60], "rx_bps": round(irx, 1), "tx_bps": round(itx, 1), "ips": ips[:6]})
        temp, temps = self.temperatures()
        procs, nprocs = self.processes()
        load = []
        if hasattr(os, "getloadavg"):
            try:
                load = [round(x, 2) for x in os.getloadavg()]
            except OSError:
                pass
        return {
            "ts": int(time.time()),
            "cpu": round(psutil.cpu_percent(None), 1),
            "cpu_per_core": [round(x, 1) for x in psutil.cpu_percent(None, percpu=True)],
            "ram": round(vm.percent, 1), "ram_used": vm.total - vm.available, "ram_total": vm.total,
            "swap": round(sw.percent, 1) if sw.total else None,
            "disk": max((d["pct"] for d in disks), default=None),
            "disks": disks,
            "net": {"rx_bps": round(rx, 1), "tx_bps": round(tx, 1), "rx_total": rx_tot, "tx_total": tx_tot},
            "interfaces": sorted(ifaces, key=lambda i: i["rx_bps"] + i["tx_bps"], reverse=True)[:16],
            "uptime": int(time.time() - psutil.boot_time()),
            "load": load,
            "temp": temp, "temps": temps,
            "processes": procs, "proc_count": nprocs,
        }


# --------------------------------------------------------------------------- transporte HTTPS

class PinError(Exception):
    pass


class AuthError(Exception):
    pass


class Transport:
    def __init__(self, cfg, timeout=20):
        u = urlparse(cfg["server_url"].rstrip("/"))
        if u.scheme not in ("https", "http"):
            raise ValueError("server_url deve começar com https://")
        if u.scheme == "http" and not cfg.get("allow_insecure_http"):
            raise ValueError("Conexão sem TLS recusada. Use https:// (ou allow_insecure_http=true apenas em testes locais).")
        self.scheme, self.host, self.port = u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80)
        self.base = u.path.rstrip("/")
        self.timeout = timeout
        self.fingerprint = (cfg.get("fingerprint") or "").replace(":", "").strip().lower()
        self.ca_file = cfg.get("ca_file") or None

    def _connect(self):
        if self.scheme == "http":
            return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        if self.fingerprint:
            # Certificado autoassinado: a confianca vem da impressao digital fixada na instalacao.
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context(cafile=self.ca_file)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=ctx)
        conn.connect()
        if self.fingerprint:
            der = conn.sock.getpeercert(binary_form=True)
            got = hashlib.sha256(der).hexdigest()
            if not hmac.compare_digest(got, self.fingerprint):
                conn.close()
                raise PinError(f"Certificado do servidor não confere com a impressão digital configurada "
                               f"(recebido {got.upper()}). Conexão abortada antes de enviar o token.")
        return conn

    def post(self, path, payload, token):
        conn = self._connect()
        try:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            conn.request("POST", self.base + path, body, {
                "Content-Type": "application/json", "Authorization": f"Bearer {token}",
                "User-Agent": f"VIGIL-Agent/{AGENT_VERSION}", "Connection": "close"})
            resp = conn.getresponse()
            data = resp.read(1_048_576)
            try:
                obj = json.loads(data.decode("utf-8") or "{}")
            except ValueError:
                obj = {}
            return resp.status, obj, resp.getheader("Retry-After")
        finally:
            conn.close()


# --------------------------------------------------------------------------- ciclo principal

class Agent:
    MAX_BATCH = 60

    def __init__(self, cfg_path, stop_event=None):
        self.cfg_path = cfg_path
        self.cfg = load_config(cfg_path)
        self.stop = stop_event or threading.Event()
        self.collector = Collector()
        self.transport = Transport(self.cfg)
        self.interval = int(self.cfg.get("interval") or 30)
        self.buffer = collections.deque(maxlen=int(self.cfg.get("buffer_max", 240)))  # ~2h com intervalo de 30 s
        self.hello_done = False

    def handle_reply(self, obj):
        iv = obj.get("interval")
        if isinstance(iv, int) and 10 <= iv <= 3600 and iv != self.interval:
            log.info("Intervalo de envio ajustado pelo servidor para %s s", iv)
            self.interval = iv
        new = obj.get("new_token")
        if isinstance(new, str) and new.startswith("vgl_") and new != self.cfg["token"]:
            cfg = dict(self.cfg, token=new)
            try:
                save_config(self.cfg_path, cfg)  # grava ANTES de usar: se falhar, segue com o token antigo
                self.cfg = cfg
                log.info("Token rotacionado com sucesso.")
            except OSError as e:
                log.error("Não foi possível gravar o token novo (%s); mantendo o atual.", e)

    def call(self, path, payload):
        status, obj, retry = self.transport.post(path, payload, self.cfg["token"])
        if status == 200:
            self.handle_reply(obj)
            return obj
        if status == 401:
            raise AuthError("Servidor recusou o token (inválido, revogado ou expirado). Peça um token novo ao administrador.")
        if status == 429:
            raise ConnectionError(f"Servidor pediu para aguardar (429). Retry-After={retry}")
        raise ConnectionError(f"Resposta inesperada do servidor: HTTP {status} {obj.get('error', '')}")

    def cycle(self):
        try:
            self.buffer.append(self.collector.sample())
            err = None
        except Exception as e:
            err = f"Falha na coleta: {e}"
            log.exception("Falha na coleta")
        if not self.hello_done:
            r = self.call("/agent/v1/hello", self.collector.system_info(self.transport.host))
            log.info("Conectado ao VIGIL como '%s' (id %s).", r.get("name"), r.get("device_id"))
            self.hello_done = True
        batch = list(self.buffer)[: self.MAX_BATCH]
        self.call("/agent/v1/report", {"samples": batch, "error": err})
        for _ in batch:
            self.buffer.popleft()
        if self.buffer:
            log.info("Enviando métricas acumuladas durante a desconexão (%s restantes)...", len(self.buffer))

    def run(self):
        log.info("VIGIL Agent %s iniciado. Servidor: %s", AGENT_VERSION, self.cfg["server_url"])
        backoff = 5
        while not self.stop.is_set():
            started = time.monotonic()
            try:
                self.cycle()
                backoff = 5
                wait = 1 if self.buffer else self.interval - (time.monotonic() - started)
            except AuthError as e:
                log.error("%s", e)
                self.hello_done = False
                wait = 300  # continua tentando devagar: o administrador pode reemitir/reativar
            except (PinError, ConnectionError, OSError, ssl.SSLError, http.client.HTTPException) as e:
                log.warning("Sem comunicação com o servidor: %s. Nova tentativa em %s s (métricas ficam em buffer).",
                            e, backoff)
                self.hello_done = False
                wait = backoff + random.uniform(0, backoff / 2)
                backoff = min(backoff * 2, 300)
            except Exception:
                log.exception("Erro inesperado")
                wait = 30
            self.stop.wait(max(1, wait))
        log.info("VIGIL Agent finalizado.")


def run_agent(cfg_path=None, stop_event=None, verbose=False):
    cfg_path = cfg_path or default_config_path()
    setup_logging(cfg_path, verbose)
    while not (stop_event and stop_event.is_set()):
        try:
            Agent(cfg_path, stop_event).run()
            return
        except (OSError, ValueError) as e:  # config ausente/invalida: aguarda e tenta de novo
            log.error("Não foi possível iniciar: %s", e)
            (stop_event or threading.Event()).wait(60)


# --------------------------------------------------------------------------- linha de comando

def main():
    ap = argparse.ArgumentParser(description="VIGIL Agent")
    ap.add_argument("--config", default=default_config_path(), help="arquivo de configuração")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("configure", help="grava servidor/token")
    c.add_argument("--server", required=True)
    c.add_argument("--token", required=True)
    c.add_argument("--fingerprint", default="", help="SHA-256 do certificado do servidor (autoassinado)")
    c.add_argument("--ca-file", default="")
    c.add_argument("--interval", type=int, default=30)
    sub.add_parser("test", help="autentica e envia uma amostra")
    sub.add_parser("collect", help="mostra as métricas coletadas")
    sub.add_parser("run", help="execução contínua")
    a = ap.parse_args()

    if a.cmd == "configure":
        if not a.token.startswith("vgl_"):
            sys.exit("Token inválido: deve começar com vgl_")
        cfg = {"server_url": a.server.rstrip("/"), "token": a.token.strip(),
               "fingerprint": a.fingerprint.replace(":", "").strip().lower(), "ca_file": a.ca_file,
               "interval": max(10, a.interval)}
        Transport(cfg)  # valida URL
        save_config(a.config, cfg)
        print(f"Configuração gravada em {a.config}")
    elif a.cmd == "collect":
        col = Collector()
        time.sleep(1.5)
        print(json.dumps({"system": col.system_info(), "sample": col.sample()}, indent=2, ensure_ascii=False))
    elif a.cmd == "test":
        setup_logging(a.config, a.verbose)
        ag = Agent(a.config)
        time.sleep(1.5)
        try:
            ag.cycle()
            print("OK: agente autenticado e métricas recebidas pelo servidor.")
        except Exception as e:
            print(f"FALHA: {e}")
            sys.exit(1)
    elif a.cmd == "run":
        stop = threading.Event()
        try:
            import signal
            signal.signal(signal.SIGTERM, lambda *_: stop.set())
        except (ImportError, ValueError):
            pass
        try:
            run_agent(a.config, stop, a.verbose)
        except KeyboardInterrupt:
            stop.set()


if __name__ == "__main__":
    main()
