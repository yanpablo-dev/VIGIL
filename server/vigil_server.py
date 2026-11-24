#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VIGIL - Servidor central de monitoramento distribuido.

* Painel web (HTTPS) para administradores.
* API dos agentes (HTTPS, comunicacao sempre iniciada pelo agente -> funciona atras de NAT).
* Autenticacao individual por dispositivo (token revogavel e rotacionavel).
* Alertas por dispositivo, registro de conexoes, rate limiting e validacao dos dados.
* Dados isolados por organizacao (org_id), pronto para evoluir para SaaS.

Somente biblioteca padrao + "cryptography" (apenas para gerar o certificado TLS na 1a execucao;
se nao houver, usa o openssl da maquina).
"""
import base64
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import logging.handlers
import mimetypes
import os
import re
import secrets
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VERSION = "1.0.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
DATA_DIR = os.environ.get("VIGIL_DATA") or os.path.join(BASE_DIR, "data")  # VIGIL_DATA = base de testes
WEB_DIR = os.path.join(BASE_DIR, "web")
AGENT_DIR = os.path.join(ROOT_DIR, "agent")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
DB_PATH = os.environ.get("VIGIL_DB") or os.path.join(DATA_DIR, "vigil.db")

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 8443,
    "tls": True,
    "cert_file": "",            # vazio = certificado autoassinado gerado em data/certs
    "key_file": "",
    "trust_proxy_headers": False,  # True somente se estiver atras de proxy confiavel (ex.: Cloudflare Tunnel)
    "retention_days": 7,
    "offline_after_seconds": 90,
    "default_interval_seconds": 30,
    "token_rotation_days": 30,     # rotacao automatica e transparente do token de cada agente
    "enrollment_valid_days": 7,    # prazo para o agente usar o token de cadastro
    "session_hours": 12,
    "max_body_bytes": 524288,
}

DEFAULT_GROUPS = ["Servidores", "Estações de trabalho", "Administrativo", "Financeiro",
                  "Infraestrutura", "Desenvolvimento", "Outros"]

DEFAULT_RULES = {
    "cpu": {"enabled": True, "warn": 75, "crit": 90, "sustain": 2},
    "ram": {"enabled": True, "warn": 75, "crit": 85},
    "disk": {"enabled": True, "warn": 80, "crit": 90},
    "temp": {"enabled": True, "warn": 75, "crit": 85},
    "offline": {"enabled": True},
    "metrics_stale": {"enabled": True},
}
METRIC_LABEL = {"cpu": "CPU", "ram": "Memória RAM", "disk": "Disco", "temp": "Temperatura"}
ROLES = {"viewer": 1, "operator": 2, "admin": 3}
TOKEN_RE = re.compile(r"^vgl_[A-Za-z0-9_-]{30,64}$")
DEVICE_ID_RE = r"([0-9a-f]{32})"

log = logging.getLogger("vigil")
CONFIG = {}
CERT_INFO = {"fingerprint": "", "spki_pin": ""}


def now():
    return int(time.time())


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- configuracao / log

def load_config():
    os.makedirs(DATA_DIR, exist_ok=True)
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg.update(json.load(f))
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    return cfg


def setup_logging():
    os.makedirs(DATA_DIR, exist_ok=True)
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = logging.handlers.RotatingFileHandler(os.path.join(DATA_DIR, "vigil.log"), maxBytes=5_000_000,
                                              backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(fh)
    log.addHandler(sh)


# --------------------------------------------------------------------------- TLS

def local_ips():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # nao envia pacotes; so escolhe a interface de saida
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    ips.discard("0.0.0.0")
    return sorted(ips)


def primary_ip():
    ips = [i for i in local_ips() if not i.startswith("127.")]
    return ips[0] if ips else "127.0.0.1"


def ensure_certificate():
    if CONFIG.get("cert_file") and CONFIG.get("key_file"):
        return CONFIG["cert_file"], CONFIG["key_file"]
    cdir = os.path.join(DATA_DIR, "certs")
    os.makedirs(cdir, exist_ok=True)
    cert, key = os.path.join(cdir, "vigil.crt"), os.path.join(cdir, "vigil.key")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    host = socket.gethostname()
    try:
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        pk = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"VIGIL {host}"),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VIGIL")])
        sans = [x509.DNSName(host), x509.DNSName("localhost")]
        for ip in set(local_ips()) | {"127.0.0.1"}:
            sans.append(x509.IPAddress(ipaddress.ip_address(ip)))
        t = datetime.datetime.now(datetime.timezone.utc)
        crt = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(pk.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(t - datetime.timedelta(days=1)).not_valid_after(t + datetime.timedelta(days=1825))
               .add_extension(x509.SubjectAlternativeName(sans), critical=False)
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .sign(pk, hashes.SHA256()))
        with open(key, "wb") as f:
            f.write(pk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
        with open(cert, "wb") as f:
            f.write(crt.public_bytes(serialization.Encoding.PEM))
    except ImportError:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-keyout", key, "-out", cert, "-days", "1825", "-subj", f"/CN=VIGIL {host}",
                        "-addext", f"subjectAltName=DNS:{host},DNS:localhost,IP:127.0.0.1,IP:{primary_ip()}"],
                       check=True, capture_output=True)
    log.info("Certificado TLS autoassinado gerado em %s", cdir)
    return cert, key


def compute_cert_info(cert_path):
    with open(cert_path, "rb") as f:
        pem = f.read().decode("ascii", "ignore")
    der = ssl.PEM_cert_to_DER_cert(pem[pem.index("-----BEGIN CERTIFICATE-----"):])
    CERT_INFO["fingerprint"] = hashlib.sha256(der).hexdigest().upper()
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        c = x509.load_der_x509_certificate(der)
        spki = c.public_key().public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
        CERT_INFO["spki_pin"] = base64.b64encode(hashlib.sha256(spki).digest()).decode()
    except ImportError:
        CERT_INFO["spki_pin"] = ""


# --------------------------------------------------------------------------- banco de dados

SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs(id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, org_id INTEGER NOT NULL REFERENCES orgs(id), username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pw TEXT NOT NULL, role TEXT NOT NULL, created_at INTEGER NOT NULL, last_login INTEGER);
CREATE TABLE IF NOT EXISTS sessions(
  id_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS device_groups(
  id INTEGER PRIMARY KEY, org_id INTEGER NOT NULL, name TEXT NOT NULL, builtin INTEGER NOT NULL DEFAULT 0,
  UNIQUE(org_id, name));
CREATE TABLE IF NOT EXISTS devices(
  id TEXT PRIMARY KEY, org_id INTEGER NOT NULL, name TEXT NOT NULL, os_declared TEXT, ip_declared TEXT,
  group_id INTEGER REFERENCES device_groups(id) ON DELETE SET NULL, location TEXT, description TEXT,
  token_hash TEXT UNIQUE, next_token_hash TEXT UNIQUE, token_created_at INTEGER,
  rotate_requested INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, enrolled_at INTEGER, last_seen INTEGER, last_metrics_at INTEGER,
  status TEXT NOT NULL DEFAULT 'pending', health TEXT NOT NULL DEFAULT 'unknown',
  hostname TEXT, os_name TEXT, os_family TEXT, ip_local TEXT, ip_remote TEXT, agent_version TEXT,
  uptime INTEGER, cpu REAL, ram REAL, disk REAL, net_rx REAL, net_tx REAL, temp REAL,
  interval INTEGER, rules TEXT, info TEXT, last_sample TEXT);
CREATE INDEX IF NOT EXISTS ix_dev_org ON devices(org_id);
CREATE TABLE IF NOT EXISTS metrics(
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, ts INTEGER NOT NULL, live INTEGER NOT NULL DEFAULT 1,
  cpu REAL, ram REAL, disk REAL, net_rx REAL, net_tx REAL, temp REAL);
CREATE INDEX IF NOT EXISTS ix_metrics ON metrics(device_id, ts);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY, org_id INTEGER NOT NULL, device_id TEXT REFERENCES devices(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, value REAL,
  opened_at INTEGER NOT NULL, updated_at INTEGER, closed_at INTEGER, acked_by TEXT, acked_at INTEGER);
CREATE INDEX IF NOT EXISTS ix_alerts_open ON alerts(device_id, kind, closed_at);
CREATE INDEX IF NOT EXISTS ix_alerts_org ON alerts(org_id, opened_at);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, org_id INTEGER, device_id TEXT, device_name TEXT, ts INTEGER NOT NULL,
  kind TEXT NOT NULL, ip TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_events ON events(org_id, ts);
CREATE TABLE IF NOT EXISTS settings(org_id INTEGER NOT NULL, key TEXT NOT NULL, value TEXT, PRIMARY KEY(org_id, key));
"""


class DB:
    """Conexao unica serializada por lock (SQLite em WAL). Suficiente para centenas de agentes."""

    def __init__(self, path):
        self.lock = threading.RLock()
        self.c = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.c.row_factory = sqlite3.Row
        self.c.execute("PRAGMA journal_mode=WAL")
        self.c.execute("PRAGMA foreign_keys=ON")
        self.c.execute("PRAGMA synchronous=NORMAL")
        self.c.executescript(SCHEMA)

    def q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.c.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        with self.lock:
            r = self.c.execute(sql, args).fetchone()
            return dict(r) if r else None

    def x(self, sql, args=()):
        with self.lock:
            cur = self.c.execute(sql, args)
            self.c.commit()
            return cur

    def many(self, sql, rows):
        with self.lock:
            self.c.executemany(sql, rows)
            self.c.commit()


db = None


def ensure_org(name="Minha organização"):
    org = db.one("SELECT id FROM orgs ORDER BY id LIMIT 1")
    if org:
        return org["id"]
    oid = db.x("INSERT INTO orgs(name, created_at) VALUES(?,?)", (name, now())).lastrowid
    seed_groups(oid)
    return oid


def seed_groups(org_id):
    for g in DEFAULT_GROUPS:
        db.x("INSERT OR IGNORE INTO device_groups(org_id, name, builtin) VALUES(?,?,1)", (org_id, g))


def get_setting(org_id, key, default=None):
    r = db.one("SELECT value FROM settings WHERE org_id=? AND key=?", (org_id, key))
    return json.loads(r["value"]) if r else default


def set_setting(org_id, key, value):
    db.x("INSERT INTO settings(org_id,key,value) VALUES(?,?,?) ON CONFLICT(org_id,key) DO UPDATE SET value=excluded.value",
         (org_id, key, json.dumps(value, ensure_ascii=False)))


def merge_rules(base, override):
    out = json.loads(json.dumps(base))
    for k, v in (override or {}).items():
        if k in out and isinstance(v, dict):
            out[k].update(v)
    return out


def org_rules(org_id):
    return merge_rules(DEFAULT_RULES, get_setting(org_id, "rules", {}))


def effective_rules(dev):
    return merge_rules(org_rules(dev["org_id"]), json.loads(dev["rules"]) if dev.get("rules") else {})


def add_event(org_id, dev, kind, ip=None, detail=None):
    db.x("INSERT INTO events(org_id, device_id, device_name, ts, kind, ip, detail) VALUES(?,?,?,?,?,?,?)",
         (org_id, dev["id"] if dev else None, dev["name"] if dev else None, now(), kind, ip, detail))


def public_url(org_id):
    u = get_setting(org_id, "public_url", "")
    if u:
        return u.rstrip("/")
    scheme = "https" if CONFIG["tls"] else "http"
    return f"{scheme}://{primary_ip()}:{CONFIG['port']}"


# --------------------------------------------------------------------------- seguranca

def hash_pw(pw):
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 240_000)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()


def check_pw(pw, stored):
    try:
        s, h = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(s), 240_000)
        return hmac.compare_digest(calc, base64.b64decode(h))
    except Exception:
        return False


def new_token():
    return "vgl_" + secrets.token_urlsafe(32)


class RateLimiter:
    """Token bucket por chave (dispositivo, IP, login...)."""

    def __init__(self):
        self.b, self.lock = {}, threading.Lock()

    def allow(self, key, per_min, burst):
        t = time.monotonic()
        with self.lock:
            tokens, last = self.b.get(key, (burst, t))
            tokens = min(burst, tokens + (t - last) * per_min / 60.0)
            ok = tokens >= 1
            self.b[key] = (tokens - 1 if ok else tokens, t)
            return ok

    def cleanup(self):
        lim = time.monotonic() - 3600
        with self.lock:
            for k in [k for k, (_, last) in self.b.items() if last < lim]:
                del self.b[k]


class FailTracker:
    """Bloqueia temporariamente IPs com muitas falhas de autenticacao."""

    def __init__(self, max_fails=10, window=600, block=900):
        self.f, self.blocked, self.lock = {}, {}, threading.Lock()
        self.max_fails, self.window, self.block = max_fails, window, block

    def is_blocked(self, ip):
        with self.lock:
            until = self.blocked.get(ip)
            if until and until > time.time():
                return True
            self.blocked.pop(ip, None)
            return False

    def fail(self, ip):
        t = time.time()
        with self.lock:
            lst = [x for x in self.f.get(ip, []) if x > t - self.window] + [t]
            self.f[ip] = lst
            if len(lst) >= self.max_fails:
                self.blocked[ip] = t + self.block
                self.f[ip] = []
                return True
        return False


RL = RateLimiter()
AGENT_FAILS = FailTracker()
LOGIN_FAILS = FailTracker(max_fails=8, window=600, block=900)
CPU_STREAK = {}


# --------------------------------------------------------------------------- validacao

def vnum(v, lo, hi):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if v != v or v < lo or v > hi:
        return None
    return round(float(v), 2)


def vstr(v, n):
    if v is None or isinstance(v, (dict, list)):
        return ""
    return str(v).replace("\x00", "")[:n]


def clean_info(d):
    d = d if isinstance(d, dict) else {}
    os_ = d.get("os") if isinstance(d.get("os"), dict) else {}
    ips = [vstr(i, 45) for i in (d.get("ips") or [])[:16] if isinstance(i, str)]
    return {
        "agent_version": vstr(d.get("agent_version"), 20),
        "hostname": vstr(d.get("hostname"), 128),
        "os": {k: vstr(os_.get(k), 160) for k in ("system", "release", "version", "pretty", "arch")},
        "ips": ips,
        "primary_ip": vstr(d.get("primary_ip"), 45),
        "boot_time": vnum(d.get("boot_time"), 0, 4e9),
        "cpu_model": vstr(d.get("cpu_model"), 160),
        "cpu_count": vnum(d.get("cpu_count"), 0, 4096),
        "cpu_threads": vnum(d.get("cpu_threads"), 0, 8192),
        "ram_total": vnum(d.get("ram_total"), 0, 1e15),
    }


def clean_sample(s, t_now):
    if not isinstance(s, dict):
        return None
    ts = vnum(s.get("ts"), 0, 4e9)
    if ts is None:
        return None
    ts = int(min(ts, t_now))
    if ts < t_now - 86400:  # descarta amostras com mais de 24h (relogio errado ou buffer antigo)
        return None
    net = s.get("net") if isinstance(s.get("net"), dict) else {}
    out = {
        "ts": ts,
        "cpu": vnum(s.get("cpu"), 0, 100),
        "cpu_per_core": [vnum(x, 0, 100) for x in (s.get("cpu_per_core") or [])[:256]],
        "ram": vnum(s.get("ram"), 0, 100),
        "ram_used": vnum(s.get("ram_used"), 0, 1e15),
        "ram_total": vnum(s.get("ram_total"), 0, 1e15),
        "swap": vnum(s.get("swap"), 0, 100),
        "disk": vnum(s.get("disk"), 0, 100),
        "uptime": vnum(s.get("uptime"), 0, 1e10),
        "load": [vnum(x, 0, 1e5) for x in (s.get("load") or [])[:3]],
        "temp": vnum(s.get("temp"), -50, 200),
        "net": {"rx_bps": vnum(net.get("rx_bps"), 0, 1e12), "tx_bps": vnum(net.get("tx_bps"), 0, 1e12),
                "rx_total": vnum(net.get("rx_total"), 0, 1e18), "tx_total": vnum(net.get("tx_total"), 0, 1e18)},
        "disks": [], "temps": [], "processes": [], "interfaces": [],
        "proc_count": vnum(s.get("proc_count"), 0, 1e7),
    }
    for d in (s.get("disks") or [])[:32]:
        if isinstance(d, dict):
            out["disks"].append({"mount": vstr(d.get("mount"), 120), "fs": vstr(d.get("fs"), 20),
                                 "total": vnum(d.get("total"), 0, 1e18), "used": vnum(d.get("used"), 0, 1e18),
                                 "pct": vnum(d.get("pct"), 0, 100)})
    for t in (s.get("temps") or [])[:32]:
        if isinstance(t, dict):
            out["temps"].append({"label": vstr(t.get("label"), 60), "c": vnum(t.get("c"), -50, 200)})
    for p in (s.get("processes") or [])[:50]:
        if isinstance(p, dict):
            out["processes"].append({"pid": vnum(p.get("pid"), 0, 1e10), "name": vstr(p.get("name"), 80),
                                     "cpu": vnum(p.get("cpu"), 0, 100), "mem": vnum(p.get("mem"), 0, 100),
                                     "mem_mb": vnum(p.get("mem_mb"), 0, 1e9)})
    for i in (s.get("interfaces") or [])[:16]:
        if isinstance(i, dict):
            out["interfaces"].append({"name": vstr(i.get("name"), 60), "rx_bps": vnum(i.get("rx_bps"), 0, 1e12),
                                      "tx_bps": vnum(i.get("tx_bps"), 0, 1e12),
                                      "ips": [vstr(x, 45) for x in (i.get("ips") or [])[:6]]})
    return out


def os_family(text):
    t = (text or "").lower()
    if "windows" in t:
        return "windows"
    if "linux" in t or "ubuntu" in t or "debian" in t or "centos" in t or "red hat" in t:
        return "linux"
    if "darwin" in t or "mac" in t:
        return "macos"
    return "other" if t else ""


# --------------------------------------------------------------------------- alertas

def open_alert(dev, kind, severity, message, value=None):
    a = db.one("SELECT id, severity FROM alerts WHERE device_id=? AND kind=? AND closed_at IS NULL", (dev["id"], kind))
    t = now()
    if a:
        if a["severity"] != severity:
            escalated = severity == "critical"
            db.x("UPDATE alerts SET severity=?, message=?, value=?, updated_at=?" +
                 (", acked_by=NULL, acked_at=NULL" if escalated else "") + " WHERE id=?",
                 (severity, message, value, t, a["id"]))
        else:
            db.x("UPDATE alerts SET message=?, value=?, updated_at=? WHERE id=?", (message, value, t, a["id"]))
        return
    db.x("INSERT INTO alerts(org_id, device_id, kind, severity, message, value, opened_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
         (dev["org_id"], dev["id"], kind, severity, message, value, t, t))
    log.warning("ALERTA [%s] %s: %s", severity, dev["name"], message)


def close_alert(dev_id, kind):
    db.x("UPDATE alerts SET closed_at=? WHERE device_id=? AND kind=? AND closed_at IS NULL", (now(), dev_id, kind))


def evaluate_sample(dev, s):
    """Avalia a amostra mais recente contra os limites e retorna a saude do dispositivo."""
    rules = effective_rules(dev)
    worst = "ok"
    for m in ("cpu", "ram", "disk", "temp"):
        v, r = s.get(m), rules[m]
        if v is None or not r.get("enabled", True):
            close_alert(dev["id"], m)
            continue
        lvl = "critical" if v >= r["crit"] else "warning" if v >= r["warn"] else "ok"
        if m == "cpu":  # CPU precisa ficar alta por N amostras seguidas (evita picos)
            streak = CPU_STREAK.get(dev["id"], 0) + 1 if lvl != "ok" else 0
            CPU_STREAK[dev["id"]] = streak
            if lvl != "ok" and streak < int(r.get("sustain", 2)):
                lvl = "ok_pending"
        if lvl in ("critical", "warning"):
            extra = ""
            if m == "disk":
                worst_disk = max((d for d in s.get("disks", []) if d.get("pct") is not None),
                                 key=lambda d: d["pct"], default=None)
                extra = f" em {worst_disk['mount']}" if worst_disk else ""
            unit = " °C" if m == "temp" else "%"
            lim = r["crit"] if lvl == "critical" else r["warn"]
            msg = f"{METRIC_LABEL[m]}{extra} em {v:.0f}{unit} (limite {lim:g}{unit})"
            open_alert(dev, m, lvl, msg, v)
        elif lvl == "ok" and v < r["warn"] - 2:  # histerese de 2 pontos
            close_alert(dev["id"], m)
    # a saude reflete os alertas de recurso ainda abertos (inclui os mantidos pela histerese)
    sev = [a["severity"] for a in db.q(
        "SELECT severity FROM alerts WHERE device_id=? AND closed_at IS NULL AND kind IN ('cpu','ram','disk','temp')",
        (dev["id"],))]
    if "critical" in sev:
        worst = "critical"
    elif sev:
        worst = "attention"
    return worst


# --------------------------------------------------------------------------- monitor em segundo plano

def monitor_loop(stop):
    last_cleanup = 0
    while not stop.wait(10):
        try:
            t = now()
            off_after = CONFIG["offline_after_seconds"]
            for dev in db.q("SELECT * FROM devices WHERE status='online' AND revoked=0"):
                rules = effective_rules(dev)
                interval = dev["interval"] or CONFIG["default_interval_seconds"]
                limit = max(off_after, interval * 3)
                if dev["last_seen"] and dev["last_seen"] < t - limit:
                    db.x("UPDATE devices SET status='offline' WHERE id=?", (dev["id"],))
                    add_event(dev["org_id"], dev, "disconnect", dev["ip_remote"],
                              f"Sem comunicação há {t - dev['last_seen']} s")
                    if rules["offline"].get("enabled", True):
                        open_alert(dev, "offline", "critical",
                                   f"Computador ficou offline (sem comunicação há {t - dev['last_seen']} s)")
                    close_alert(dev["id"], "metrics_stale")
                    continue
                if rules["metrics_stale"].get("enabled", True):
                    lm = dev["last_metrics_at"] or dev["enrolled_at"] or t
                    if lm < t - max(limit, interval * 4):
                        open_alert(dev, "metrics_stale", "warning",
                                   f"Agente parou de enviar métricas (última há {t - lm} s), mas segue respondendo")
            # rotacao automatica de tokens
            rot_days = CONFIG.get("token_rotation_days") or 0
            if rot_days > 0:
                db.x("UPDATE devices SET rotate_requested=1 WHERE revoked=0 AND enrolled_at IS NOT NULL "
                     "AND rotate_requested=0 AND token_created_at < ?", (t - rot_days * 86400,))
            if t - last_cleanup > 3600:
                last_cleanup = t
                ret = t - CONFIG["retention_days"] * 86400
                db.x("DELETE FROM metrics WHERE ts < ?", (ret,))
                db.x("DELETE FROM events WHERE ts < ?", (t - 90 * 86400,))
                db.x("DELETE FROM alerts WHERE closed_at IS NOT NULL AND closed_at < ?", (t - 90 * 86400,))
                db.x("DELETE FROM sessions WHERE expires_at < ?", (t,))
                RL.cleanup()
        except Exception:
            log.exception("Falha no monitor")


# --------------------------------------------------------------------------- roteamento

class ApiError(Exception):
    def __init__(self, status, msg, headers=None):
        super().__init__(msg)
        self.status, self.msg, self.headers = status, msg, headers or {}


ROUTES = []


def route(method, pattern, auth="viewer"):
    def deco(fn):
        ROUTES.append((method, re.compile("^" + pattern + "$"), fn, auth))
        return fn
    return deco


def require(cond, msg, status=400):
    if not cond:
        raise ApiError(status, msg)


def get_device(org_id, dev_id):
    d = db.one("SELECT * FROM devices WHERE id=? AND org_id=?", (dev_id, org_id))
    require(d, "Dispositivo não encontrado", 404)
    return d


def device_status(d, t=None):
    t = t or now()
    if d["revoked"]:
        return "revoked"
    if not d["enrolled_at"]:
        if (d["token_created_at"] or d["created_at"]) < t - CONFIG["enrollment_valid_days"] * 86400:
            return "expired"
        return "pending"
    return d["status"]


DEVICE_COLS = ("id, org_id, name, os_declared, ip_declared, group_id, location, description, token_created_at, "
               "rotate_requested, revoked, created_at, enrolled_at, last_seen, last_metrics_at, status, health, "
               "hostname, os_name, os_family, ip_local, ip_remote, agent_version, uptime, cpu, ram, disk, net_rx, "
               "net_tx, temp, interval, rules")


def public_device(d, groups=None, open_alerts=None):
    out = {k: d.get(k) for k in DEVICE_COLS.replace(" ", "").split(",") if k in d}
    out["status"] = device_status(d)
    out["os_family"] = d.get("os_family") or os_family(d.get("os_declared"))
    out["rules"] = json.loads(d["rules"]) if d.get("rules") else {}
    if groups is not None:
        out["group_name"] = groups.get(d["group_id"], "")
    if open_alerts is not None:
        out["open_alerts"] = open_alerts.get(d["id"], 0)
    return out


def group_map(org_id):
    return {g["id"]: g["name"] for g in db.q("SELECT id, name FROM device_groups WHERE org_id=?", (org_id,))}


def resolve_group(org_id, gid):
    if gid in (None, ""):
        g = db.one("SELECT id FROM device_groups WHERE org_id=? AND name='Outros'", (org_id,))
        return g["id"] if g else None
    try:
        gid = int(gid)
    except (TypeError, ValueError):
        raise ApiError(400, "Grupo inválido")
    require(db.one("SELECT id FROM device_groups WHERE id=? AND org_id=?", (gid, org_id)), "Grupo inválido")
    return gid


# ----------------------------------------------------------------- rotas: setup / sessao

@route("GET", "/api/setup-status", auth="public")
def h_setup_status(h, m, user, body):
    return {"needs_setup": db.one("SELECT COUNT(*) n FROM users")["n"] == 0, "version": VERSION}


@route("POST", "/api/setup", auth="public")
def h_setup(h, m, user, body):
    require(db.one("SELECT COUNT(*) n FROM users")["n"] == 0, "Configuração inicial já realizada", 403)
    require(h.is_loopback(), "A configuração inicial só pode ser feita no próprio servidor (localhost)", 403)
    username, pw = vstr(body.get("username"), 40).strip(), vstr(body.get("password"), 200)
    require(re.match(r"^[A-Za-z0-9_.-]{3,40}$", username), "Usuário inválido (3-40 letras, números, . _ -)")
    require(len(pw) >= 10, "A senha deve ter pelo menos 10 caracteres")
    org_id = ensure_org()
    org_name = vstr(body.get("org_name"), 80).strip()
    if org_name:
        db.x("UPDATE orgs SET name=? WHERE id=?", (org_name, org_id))
    db.x("INSERT INTO users(org_id, username, pw, role, created_at) VALUES(?,?,?,?,?)",
         (org_id, username, hash_pw(pw), "admin", now()))
    return {"ok": True}


@route("POST", "/api/login", auth="public")
def h_login(h, m, user, body):
    ip = h.client_ip()
    if LOGIN_FAILS.is_blocked(ip):
        raise ApiError(429, "Muitas tentativas. Aguarde alguns minutos.")
    if not RL.allow(("login", ip), 10, 5):
        raise ApiError(429, "Muitas tentativas. Aguarde um momento.")
    username, pw = vstr(body.get("username"), 40).strip(), vstr(body.get("password"), 200)
    u = db.one("SELECT * FROM users WHERE username=?", (username,))
    if not u or not check_pw(pw, u["pw"]):
        LOGIN_FAILS.fail(ip)
        add_event(u["org_id"] if u else None, None, "login_fail", ip, f"Usuário: {username}")
        raise ApiError(401, "Usuário ou senha incorretos")
    sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    exp = now() + CONFIG["session_hours"] * 3600
    db.x("INSERT INTO sessions(id_hash, user_id, csrf, expires_at) VALUES(?,?,?,?)", (sha(sid), u["id"], csrf, exp))
    db.x("UPDATE users SET last_login=? WHERE id=?", (now(), u["id"]))
    add_event(u["org_id"], None, "login", ip, f"Usuário: {u['username']}")
    secure = "; Secure" if CONFIG["tls"] else ""
    h.extra_headers.append(("Set-Cookie", f"vigil_session={sid}; HttpOnly; SameSite=Strict; Path=/; "
                                          f"Max-Age={CONFIG['session_hours'] * 3600}{secure}"))
    return {"ok": True, "csrf": csrf}


@route("POST", "/api/logout")
def h_logout(h, m, user, body):
    db.x("DELETE FROM sessions WHERE id_hash=?", (user["session_hash"],))
    h.extra_headers.append(("Set-Cookie", "vigil_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"))
    return {"ok": True}


@route("GET", "/api/me")
def h_me(h, m, user, body):
    org = db.one("SELECT name FROM orgs WHERE id=?", (user["org_id"],))
    return {"username": user["username"], "role": user["role"], "csrf": user["csrf"],
            "org": org["name"] if org else "", "version": VERSION}


@route("POST", "/api/me/password")
def h_me_password(h, m, user, body):
    u = db.one("SELECT pw FROM users WHERE id=?", (user["id"],))
    require(check_pw(vstr(body.get("current"), 200), u["pw"]), "Senha atual incorreta", 403)
    pw = vstr(body.get("password"), 200)
    require(len(pw) >= 10, "A senha deve ter pelo menos 10 caracteres")
    db.x("UPDATE users SET pw=? WHERE id=?", (hash_pw(pw), user["id"]))
    db.x("DELETE FROM sessions WHERE user_id=? AND id_hash<>?", (user["id"], user["session_hash"]))
    return {"ok": True}


# ----------------------------------------------------------------- rotas: usuarios

@route("GET", "/api/users", auth="admin")
def h_users(h, m, user, body):
    return db.q("SELECT id, username, role, created_at, last_login FROM users WHERE org_id=? ORDER BY username",
                (user["org_id"],))


@route("POST", "/api/users", auth="admin")
def h_user_create(h, m, user, body):
    username, pw, role = vstr(body.get("username"), 40).strip(), vstr(body.get("password"), 200), body.get("role")
    require(re.match(r"^[A-Za-z0-9_.-]{3,40}$", username), "Usuário inválido")
    require(len(pw) >= 10, "A senha deve ter pelo menos 10 caracteres")
    require(role in ROLES, "Perfil inválido")
    require(not db.one("SELECT id FROM users WHERE username=?", (username,)), "Usuário já existe")
    db.x("INSERT INTO users(org_id, username, pw, role, created_at) VALUES(?,?,?,?,?)",
         (user["org_id"], username, hash_pw(pw), role, now()))
    return {"ok": True}


@route("DELETE", r"/api/users/(\d+)", auth="admin")
def h_user_delete(h, m, user, body):
    uid = int(m.group(1))
    require(uid != user["id"], "Você não pode excluir o próprio usuário")
    db.x("DELETE FROM users WHERE id=? AND org_id=?", (uid, user["org_id"]))
    return {"ok": True}


# ----------------------------------------------------------------- rotas: servidor / config

def needs_pinning(url):
    """Certificado autoassinado deste servidor -> agentes fixam a impressao digital.
    Endereco publico por nome de dominio (ex.: Cloudflare/proxy com certificado valido) -> validacao normal pela CA."""
    if not CONFIG["tls"] or CONFIG.get("cert_file"):
        return False
    host = urlparse(url).hostname or ""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return host.lower() in ("localhost", socket.gethostname().lower())


@route("GET", "/api/server-info")
def h_server_info(h, m, user, body):
    url = public_url(user["org_id"])
    return {"public_url": url, "pin": needs_pinning(url), "fingerprint": CERT_INFO["fingerprint"],
            "spki_pin": CERT_INFO["spki_pin"], "tls": CONFIG["tls"], "version": VERSION,
            "default_interval": CONFIG["default_interval_seconds"], "local_ips": local_ips(),
            "port": CONFIG["port"], "custom_public_url": get_setting(user["org_id"], "public_url", "")}


@route("GET", "/api/settings")
def h_settings(h, m, user, body):
    return {"rules": org_rules(user["org_id"]), "public_url": get_setting(user["org_id"], "public_url", ""),
            "retention_days": CONFIG["retention_days"], "offline_after_seconds": CONFIG["offline_after_seconds"],
            "token_rotation_days": CONFIG["token_rotation_days"]}


def clean_rules(raw):
    out = {}
    if not isinstance(raw, dict):
        return out
    for k in ("cpu", "ram", "disk", "temp"):
        r = raw.get(k)
        if isinstance(r, dict):
            c = {}
            if "enabled" in r:
                c["enabled"] = bool(r["enabled"])
            for f, lo, hi in (("warn", 1, 150), ("crit", 1, 150), ("sustain", 1, 20)):
                if f in r and r[f] not in (None, ""):
                    v = vnum(float(r[f]) if isinstance(r[f], str) else r[f], lo, hi)
                    require(v is not None, f"Valor inválido em {k}.{f}")
                    c[f] = v
            if "warn" in c and "crit" in c:
                require(c["warn"] <= c["crit"], f"{METRIC_LABEL[k]}: atenção deve ser menor ou igual ao crítico")
            out[k] = c
    for k in ("offline", "metrics_stale"):
        r = raw.get(k)
        if isinstance(r, dict) and "enabled" in r:
            out[k] = {"enabled": bool(r["enabled"])}
    return out


@route("PUT", "/api/settings", auth="admin")
def h_settings_put(h, m, user, body):
    if "rules" in body:
        set_setting(user["org_id"], "rules", clean_rules(body["rules"]))
    if "public_url" in body:
        u = vstr(body["public_url"], 200).strip().rstrip("/")
        require(u == "" or re.match(r"^https?://[A-Za-z0-9.\-\[\]:]+(:\d+)?(/[\w\-./]*)?$", u), "Endereço público inválido")
        set_setting(user["org_id"], "public_url", u)
    return {"ok": True}


# ----------------------------------------------------------------- rotas: grupos

@route("GET", "/api/groups")
def h_groups(h, m, user, body):
    return db.q("SELECT g.id, g.name, g.builtin, COUNT(d.id) AS devices FROM device_groups g "
                "LEFT JOIN devices d ON d.group_id=g.id WHERE g.org_id=? GROUP BY g.id ORDER BY g.builtin DESC, g.name",
                (user["org_id"],))


@route("POST", "/api/groups", auth="operator")
def h_group_create(h, m, user, body):
    name = vstr(body.get("name"), 60).strip()
    require(name, "Informe o nome do grupo")
    require(not db.one("SELECT id FROM device_groups WHERE org_id=? AND name=?", (user["org_id"], name)),
            "Já existe um grupo com esse nome")
    gid = db.x("INSERT INTO device_groups(org_id, name) VALUES(?,?)", (user["org_id"], name)).lastrowid
    return {"id": gid}


@route("PATCH", r"/api/groups/(\d+)", auth="operator")
def h_group_rename(h, m, user, body):
    name = vstr(body.get("name"), 60).strip()
    require(name, "Informe o nome do grupo")
    g = db.one("SELECT * FROM device_groups WHERE id=? AND org_id=?", (int(m.group(1)), user["org_id"]))
    require(g, "Grupo não encontrado", 404)
    require(g["name"] != "Outros", "O grupo 'Outros' não pode ser renomeado")
    require(not db.one("SELECT id FROM device_groups WHERE org_id=? AND name=? AND id<>?", (user["org_id"], name, g["id"])),
            "Já existe um grupo com esse nome")
    db.x("UPDATE device_groups SET name=? WHERE id=?", (name, g["id"]))
    return {"ok": True}


@route("DELETE", r"/api/groups/(\d+)", auth="operator")
def h_group_delete(h, m, user, body):
    g = db.one("SELECT * FROM device_groups WHERE id=? AND org_id=?", (int(m.group(1)), user["org_id"]))
    require(g, "Grupo não encontrado", 404)
    require(g["name"] != "Outros", "O grupo 'Outros' não pode ser excluído")
    db.x("UPDATE devices SET group_id=? WHERE group_id=? AND org_id=?",
         (resolve_group(user["org_id"], None), g["id"], user["org_id"]))
    db.x("DELETE FROM device_groups WHERE id=?", (g["id"],))
    return {"ok": True}


@route("POST", "/api/devices/move", auth="operator")
def h_devices_move(h, m, user, body):
    gid = resolve_group(user["org_id"], body.get("group_id"))
    ids = [i for i in (body.get("device_ids") or []) if isinstance(i, str) and re.match("^" + DEVICE_ID_RE + "$", i)]
    require(ids, "Selecione ao menos um dispositivo")
    for i in ids[:1000]:
        db.x("UPDATE devices SET group_id=? WHERE id=? AND org_id=?", (gid, i, user["org_id"]))
    return {"ok": True, "moved": len(ids)}


# ----------------------------------------------------------------- rotas: dispositivos

def open_alert_counts(org_id):
    return {r["device_id"]: r["n"] for r in db.q(
        "SELECT device_id, COUNT(*) n FROM alerts WHERE org_id=? AND closed_at IS NULL GROUP BY device_id", (org_id,))}


@route("GET", "/api/devices")
def h_devices(h, m, user, body):
    org = user["org_id"]
    groups, oa = group_map(org), open_alert_counts(org)
    devs = [public_device(d, groups, oa) for d in db.q(f"SELECT {DEVICE_COLS} FROM devices WHERE org_id=? ORDER BY name COLLATE NOCASE", (org,))]
    q = h.query
    st = (q.get("status") or [""])[0]
    if st in ("online", "offline", "pending", "revoked", "expired"):
        devs = [d for d in devs if d["status"] == st]
    elif st == "critical":
        devs = [d for d in devs if d["status"] == "online" and d["health"] == "critical"]
    elif st == "attention":
        devs = [d for d in devs if d["status"] == "online" and d["health"] == "attention"]
    if (q.get("os") or [""])[0]:
        devs = [d for d in devs if d["os_family"] == q["os"][0]]
    if (q.get("group") or [""])[0]:
        devs = [d for d in devs if str(d["group_id"]) == q["group"][0]]
    if (q.get("location") or [""])[0]:
        devs = [d for d in devs if (d["location"] or "") == q["location"][0]]
    if (q.get("q") or [""])[0]:
        term = q["q"][0].lower()
        devs = [d for d in devs if term in " ".join(str(d.get(k) or "") for k in
                ("name", "hostname", "ip_local", "ip_remote", "ip_declared", "description", "location")).lower()]
    return devs


@route("POST", "/api/devices", auth="admin")
def h_device_create(h, m, user, body):
    org = user["org_id"]
    name = vstr(body.get("name"), 80).strip()
    require(name, "Informe o nome do dispositivo")
    require(not db.one("SELECT id FROM devices WHERE org_id=? AND name=?", (org, name)), "Já existe um dispositivo com esse nome")
    ip = vstr(body.get("ip"), 45).strip()
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ApiError(400, "Endereço IP inválido")
    os_decl = vstr(body.get("os"), 40).strip()
    require(os_decl in ("Windows", "Linux", "Outro", ""), "Sistema operacional inválido")
    token, dev_id, t = new_token(), uuid.uuid4().hex, now()
    db.x("INSERT INTO devices(id, org_id, name, os_declared, ip_declared, group_id, location, description, token_hash, "
         "token_created_at, created_at, status, os_family, interval) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
         (dev_id, org, name, os_decl, ip, resolve_group(org, body.get("group_id")), vstr(body.get("location"), 80).strip(),
          vstr(body.get("description"), 500).strip(), sha(token), t, t, "pending", os_family(os_decl),
          CONFIG["default_interval_seconds"]))
    dev = db.one("SELECT * FROM devices WHERE id=?", (dev_id,))
    add_event(org, dev, "device_created", h.client_ip(), f"Cadastrado por {user['username']}")
    return {"device": public_device(dev), "token": token,
            "token_expires_at": t + CONFIG["enrollment_valid_days"] * 86400}


@route("GET", "/api/devices/" + DEVICE_ID_RE)
def h_device_get(h, m, user, body):
    d = get_device(user["org_id"], m.group(1))
    out = public_device(d, group_map(user["org_id"]))
    out["info"] = json.loads(d["info"]) if d["info"] else {}
    out["last_sample"] = json.loads(d["last_sample"]) if d["last_sample"] else None
    out["effective_rules"] = effective_rules(d)
    out["alerts"] = db.q("SELECT * FROM alerts WHERE device_id=? ORDER BY closed_at IS NOT NULL, opened_at DESC LIMIT 30", (d["id"],))
    out["events"] = db.q("SELECT ts, kind, ip, detail FROM events WHERE device_id=? ORDER BY ts DESC LIMIT 30", (d["id"],))
    out["token_rotation_pending"] = bool(d["rotate_requested"] or d["next_token_hash"])
    return out


@route("PATCH", "/api/devices/" + DEVICE_ID_RE, auth="operator")
def h_device_update(h, m, user, body):
    d = get_device(user["org_id"], m.group(1))
    sets, args = [], []
    if "name" in body:
        name = vstr(body["name"], 80).strip()
        require(name, "Informe o nome")
        require(not db.one("SELECT id FROM devices WHERE org_id=? AND name=? AND id<>?", (d["org_id"], name, d["id"])),
                "Já existe um dispositivo com esse nome")
        sets.append("name=?"); args.append(name)
    if "ip" in body:
        ip = vstr(body["ip"], 45).strip()
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ApiError(400, "Endereço IP inválido")
        sets.append("ip_declared=?"); args.append(ip)
    if "os" in body:
        require(body["os"] in ("Windows", "Linux", "Outro", ""), "Sistema operacional inválido")
        sets.append("os_declared=?"); args.append(body["os"])
    for k, n in (("location", 80), ("description", 500)):
        if k in body:
            sets.append(f"{k}=?"); args.append(vstr(body[k], n).strip())
    if "group_id" in body:
        sets.append("group_id=?"); args.append(resolve_group(d["org_id"], body["group_id"]))
    if "rules" in body:
        require(ROLES[user["role"]] >= ROLES["admin"], "Somente administradores alteram limites", 403)
        sets.append("rules=?"); args.append(json.dumps(clean_rules(body["rules"])))
    if "interval" in body:
        iv = vnum(body["interval"], 10, 3600)
        require(iv, "Intervalo inválido (10 a 3600 s)")
        sets.append("interval=?"); args.append(int(iv))
    if sets:
        db.x(f"UPDATE devices SET {', '.join(sets)} WHERE id=?", (*args, d["id"]))
    return {"ok": True}


@route("DELETE", "/api/devices/" + DEVICE_ID_RE, auth="admin")
def h_device_delete(h, m, user, body):
    d = get_device(user["org_id"], m.group(1))
    db.x("DELETE FROM devices WHERE id=?", (d["id"],))
    add_event(d["org_id"], d, "device_deleted", h.client_ip(), f"Excluído por {user['username']}")
    return {"ok": True}


@route("POST", "/api/devices/" + DEVICE_ID_RE + "/rotate", auth="admin")
def h_device_rotate(h, m, user, body):
    d = get_device(user["org_id"], m.group(1))
    require(not d["revoked"], "Dispositivo revogado: use 'Reemitir token'")
    require(d["enrolled_at"], "O agente ainda não se conectou: use 'Reemitir token'")
    db.x("UPDATE devices SET rotate_requested=1 WHERE id=?", (d["id"],))
    add_event(d["org_id"], d, "token_rotation_requested", h.client_ip(), f"Solicitado por {user['username']}")
    return {"ok": True}


@route("POST", "/api/devices/" + DEVICE_ID_RE + "/revoke", auth="admin")
def h_device_revoke(h, m, user, body):
    d = get_device(user["org_id"], m.group(1))
    # mantem o hash do token para identificar (e registrar) tentativas do agente revogado
    db.x("UPDATE devices SET revoked=1, next_token_hash=NULL, rotate_requested=0, status='offline' WHERE id=?",
         (d["id"],))
    close_alert(d["id"], "offline")
    close_alert(d["id"], "metrics_stale")
    add_event(d["org_id"], d, "token_revoked", h.client_ip(), f"Revogado por {user['username']}")
    return {"ok": True}


@route("POST", "/api/devices/" + DEVICE_ID_RE + "/reissue", auth="admin")
def h_device_reissue(h, m, user, body):
    d = get_device(user["org_id"], m.group(1))
    token, t = new_token(), now()
    db.x("UPDATE devices SET revoked=0, token_hash=?, next_token_hash=NULL, rotate_requested=0, token_created_at=?, "
         "enrolled_at=NULL, status='pending' WHERE id=?", (sha(token), t, d["id"]))
    add_event(d["org_id"], d, "token_reissued", h.client_ip(), f"Reemitido por {user['username']}")
    return {"token": token, "token_expires_at": t + CONFIG["enrollment_valid_days"] * 86400}


RANGES = {"1h": (3600, 30), "6h": (21600, 120), "24h": (86400, 600), "7d": (604800, 3600)}


@route("GET", "/api/devices/" + DEVICE_ID_RE + "/metrics")
def h_device_metrics(h, m, user, body):
    d = get_device(user["org_id"], m.group(1))
    span, bucket = RANGES.get((h.query.get("range") or ["1h"])[0], RANGES["1h"])
    rows = db.q("SELECT (ts/?)*? AS t, AVG(cpu) cpu, AVG(ram) ram, AVG(disk) disk, AVG(net_rx) net_rx, "
                "AVG(net_tx) net_tx, AVG(temp) temp FROM metrics WHERE device_id=? AND ts>=? GROUP BY t ORDER BY t",
                (bucket, bucket, d["id"], now() - span))
    return {"bucket": bucket, "span": span, "points": rows}


# ----------------------------------------------------------------- rotas: alertas / eventos / resumo

@route("GET", "/api/alerts")
def h_alerts(h, m, user, body):
    state = (h.query.get("state") or ["open"])[0]
    dev = (h.query.get("device") or [""])[0]
    sql = ("SELECT a.*, d.name AS device_name, d.location, g.name AS group_name FROM alerts a "
           "LEFT JOIN devices d ON d.id=a.device_id LEFT JOIN device_groups g ON g.id=d.group_id WHERE a.org_id=?")
    args = [user["org_id"]]
    if state == "open":
        sql += " AND a.closed_at IS NULL"
    if dev:
        sql += " AND a.device_id=?"; args.append(dev)
    sql += " ORDER BY a.closed_at IS NOT NULL, CASE a.severity WHEN 'critical' THEN 0 ELSE 1 END, a.opened_at DESC LIMIT 500"
    return db.q(sql, args)


@route("POST", r"/api/alerts/(\d+)/ack", auth="operator")
def h_alert_ack(h, m, user, body):
    db.x("UPDATE alerts SET acked_by=?, acked_at=? WHERE id=? AND org_id=?",
         (user["username"], now(), int(m.group(1)), user["org_id"]))
    return {"ok": True}


@route("GET", "/api/events")
def h_events(h, m, user, body):
    kind = (h.query.get("kind") or [""])[0]
    try:
        limit = max(1, min(1000, int((h.query.get("limit") or ["300"])[0])))
    except ValueError:
        limit = 300
    # tentativas com token desconhecido nao pertencem a nenhuma organizacao: visiveis ao admin da organizacao principal
    sql, args = "SELECT * FROM events WHERE (org_id=? OR (org_id IS NULL AND ?))", \
        [user["org_id"], 1 if user["role"] == "admin" and user["org_id"] == ensure_org() else 0]
    if kind:
        sql += " AND kind=?"; args.append(kind)
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    return db.q(sql, args)


@route("GET", "/api/summary")
def h_summary(h, m, user, body):
    org, t = user["org_id"], now()
    groups, oa = group_map(org), open_alert_counts(org)
    devs = [public_device(d, groups, oa) for d in db.q(f"SELECT {DEVICE_COLS} FROM devices WHERE org_id=?", (org,))]
    online = [d for d in devs if d["status"] == "online"]
    enrolled = [d for d in devs if d["enrolled_at"] and d["status"] in ("online", "offline")]

    def avg(key):
        vals = [d[key] for d in online if d[key] is not None]
        return round(sum(vals) / len(vals), 1) if vals else None

    counts = {r["device_id"]: r["n"] for r in db.q(
        "SELECT device_id, COUNT(*) n FROM metrics m JOIN devices d ON d.id=m.device_id "
        "WHERE d.org_id=? AND m.ts>=? AND m.live=1 GROUP BY device_id", (org, t - 86400))}
    ratios = []
    for d in enrolled:
        since = max(t - 86400, d["enrolled_at"])
        expected = (t - since) / (d["interval"] or CONFIG["default_interval_seconds"])
        if expected >= 2:
            ratios.append(min(1.0, counts.get(d["id"], 0) / expected))
        elif d["status"] == "online":
            ratios.append(1.0)
    sev = {r["severity"]: r["n"] for r in db.q(
        "SELECT severity, COUNT(*) n FROM alerts WHERE org_id=? AND closed_at IS NULL GROUP BY severity", (org,))}
    by_os, by_group = {}, {}
    for d in devs:
        by_os[d["os_family"] or "other"] = by_os.get(d["os_family"] or "other", 0) + 1
        by_group[d["group_name"] or "Sem grupo"] = by_group.get(d["group_name"] or "Sem grupo", 0) + 1
    return {
        "total": len(devs), "online": len(online),
        "offline": len([d for d in devs if d["status"] == "offline"]),
        "pending": len([d for d in devs if d["status"] in ("pending", "expired")]),
        "revoked": len([d for d in devs if d["status"] == "revoked"]),
        "critical": len([d for d in online if d["health"] == "critical"]),
        "attention": len([d for d in online if d["health"] == "attention"]),
        "avg_cpu": avg("cpu"), "avg_ram": avg("ram"), "avg_disk": avg("disk"),
        "availability": round(100 * sum(ratios) / len(ratios), 1) if ratios else None,
        "alerts_critical": sev.get("critical", 0), "alerts_warning": sev.get("warning", 0),
        "last_connects": db.q("SELECT * FROM events WHERE org_id=? AND kind IN ('connect','enrolled') ORDER BY ts DESC LIMIT 8", (org,)),
        "last_disconnects": db.q("SELECT * FROM events WHERE org_id=? AND kind='disconnect' ORDER BY ts DESC LIMIT 8", (org,)),
        "recent_alerts": db.q("SELECT a.*, d.name AS device_name FROM alerts a LEFT JOIN devices d ON d.id=a.device_id "
                              "WHERE a.org_id=? AND a.closed_at IS NULL ORDER BY CASE a.severity WHEN 'critical' THEN 0 ELSE 1 END, "
                              "a.opened_at DESC LIMIT 8", (org,)),
        "by_os": by_os, "by_group": by_group, "devices": devs, "server_time": t,
    }


# ----------------------------------------------------------------- rotas: agente

def agent_auth(h):
    ip = h.client_ip()
    if AGENT_FAILS.is_blocked(ip):
        raise ApiError(429, "IP temporariamente bloqueado por falhas de autenticação", {"Retry-After": "900"})
    if not RL.allow(("agent-ip", ip), 600, 120):
        raise ApiError(429, "Limite de requisições excedido", {"Retry-After": "30"})
    auth = h.headers.get("Authorization", "")
    tok = auth[7:].strip() if auth.startswith("Bearer ") else ""

    def fail(reason, dev=None):
        blocked = AGENT_FAILS.fail(ip)
        add_event(dev["org_id"] if dev else None, dev, "auth_fail", ip, reason + (" (IP bloqueado 15 min)" if blocked else ""))
        log.warning("Agente recusado de %s: %s", ip, reason)
        raise ApiError(401, "Não autorizado")

    if not TOKEN_RE.match(tok):
        fail("Token ausente ou em formato inválido")
    th = sha(tok)
    dev = db.one("SELECT * FROM devices WHERE token_hash=? OR next_token_hash=?", (th, th))
    if not dev:
        fail("Token desconhecido ou revogado")
    if dev["revoked"]:
        fail("Dispositivo revogado", dev)
    if not dev["enrolled_at"] and dev["token_created_at"] < now() - CONFIG["enrollment_valid_days"] * 86400:
        fail("Token de cadastro expirado", dev)
    if not RL.allow(("agent-dev", dev["id"]), 30, 20):
        raise ApiError(429, "Limite de requisições do dispositivo excedido", {"Retry-After": "30"})
    if dev["next_token_hash"] == th:  # agente adotou o token novo -> efetiva a rotacao
        db.x("UPDATE devices SET token_hash=?, next_token_hash=NULL, token_created_at=?, rotate_requested=0 WHERE id=?",
             (th, now(), dev["id"]))
        add_event(dev["org_id"], dev, "token_rotated", ip, "Token rotacionado automaticamente pelo agente")
        dev = db.one("SELECT * FROM devices WHERE id=?", (dev["id"],))
    return dev, ip


def mark_seen(dev, ip):
    t = now()
    first = not dev["enrolled_at"]
    was_offline = dev["status"] != "online"
    db.x("UPDATE devices SET last_seen=?, status='online', ip_remote=?, enrolled_at=COALESCE(enrolled_at, ?) WHERE id=?",
         (t, ip, t, dev["id"]))
    if first:
        add_event(dev["org_id"], dev, "enrolled", ip, "Agente autenticado pela primeira vez")
    elif was_offline:
        add_event(dev["org_id"], dev, "connect", ip, "Reconectado")
        close_alert(dev["id"], "offline")


def agent_reply(dev):
    out = {"ok": True, "device_id": dev["id"], "name": dev["name"],
           "interval": dev["interval"] or CONFIG["default_interval_seconds"], "server_time": now()}
    if dev["rotate_requested"]:
        new = new_token()
        db.x("UPDATE devices SET next_token_hash=? WHERE id=?", (sha(new), dev["id"]))
        out["new_token"] = new
    return out


@route("POST", "/agent/v1/hello", auth="agent")
def h_agent_hello(h, m, dev, body):
    dev, ip = dev
    info = clean_info(body)
    os_ = info["os"]
    os_name = os_["pretty"] or f"{os_['system']} {os_['release']}".strip()
    mark_seen(dev, ip)
    db.x("UPDATE devices SET hostname=?, os_name=?, os_family=?, ip_local=?, agent_version=?, info=? WHERE id=?",
         (info["hostname"], os_name, os_family(os_name or os_["system"]), info["primary_ip"] or (info["ips"][0] if info["ips"] else ""),
          info["agent_version"], json.dumps(info, ensure_ascii=False), dev["id"]))
    return agent_reply(dev)


@route("POST", "/agent/v1/report", auth="agent")
def h_agent_report(h, m, dev, body):
    dev, ip = dev
    t = now()
    mark_seen(dev, ip)
    raw = body.get("samples") if isinstance(body.get("samples"), list) else []
    samples = [s for s in (clean_sample(x, t) for x in raw[:120]) if s]
    interval = dev["interval"] or CONFIG["default_interval_seconds"]
    if samples:
        samples.sort(key=lambda s: s["ts"])
        db.many("INSERT INTO metrics(device_id, ts, live, cpu, ram, disk, net_rx, net_tx, temp) VALUES(?,?,?,?,?,?,?,?,?)",
                [(dev["id"], s["ts"], 1 if s["ts"] >= t - 2 * interval else 0, s["cpu"], s["ram"], s["disk"],
                  s["net"]["rx_bps"], s["net"]["tx_bps"], s["temp"]) for s in samples])
        last = samples[-1]
        health = evaluate_sample(dev, last)
        db.x("UPDATE devices SET last_metrics_at=?, health=?, cpu=?, ram=?, disk=?, net_rx=?, net_tx=?, temp=?, uptime=?, "
             "last_sample=? WHERE id=?",
             (t, health, last["cpu"], last["ram"], last["disk"], last["net"]["rx_bps"], last["net"]["tx_bps"], last["temp"],
              int(last["uptime"]) if last["uptime"] is not None else None, json.dumps(last, ensure_ascii=False), dev["id"]))
        close_alert(dev["id"], "metrics_stale")
    err = vstr(body.get("error"), 300)
    if err:
        log.info("Agente %s informou erro de coleta: %s", dev["name"], err)
    return agent_reply(dev)


# ----------------------------------------------------------------- downloads do agente

DOWNLOADS = {
    "windows": {"vigil_agent.py": "vigil_agent.py", "vigil_service.py": "windows/vigil_service.py",
                "install.ps1": "windows/install.ps1", "uninstall.ps1": "windows/uninstall.ps1",
                "build_exe.ps1": "windows/build_exe.ps1", "LEIA-ME.txt": "windows/LEIA-ME.txt"},
    "linux": {"vigil_agent.py": "vigil_agent.py", "install.sh": "linux/install.sh",
              "uninstall.sh": "linux/uninstall.sh", "vigil-agent.service": "linux/vigil-agent.service",
              "LEIA-ME.txt": "linux/LEIA-ME.txt"},
}


def read_agent_file(rel):
    p = os.path.normpath(os.path.join(AGENT_DIR, rel))
    require(p.startswith(os.path.normpath(AGENT_DIR)) and os.path.isfile(p), "Arquivo não encontrado", 404)
    with open(p, "rb") as f:
        return f.read()


# --------------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "VIGIL"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30

    def log_message(self, fmt, *args):
        pass

    def client_ip(self):
        ip = self.client_address[0]
        if CONFIG.get("trust_proxy_headers"):
            fwd = self.headers.get("CF-Connecting-IP") or (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
            if fwd:
                ip = fwd
        return ip[:45]

    def is_loopback(self):
        try:
            return ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            return False

    def send(self, status, data, ctype, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        if CONFIG["tls"]:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        for k, v in self.extra_headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_json(self, status, obj, headers=None):
        hd = {"Cache-Control": "no-store"}
        hd.update(headers or {})
        self.send(status, json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"),
                  "application/json; charset=utf-8", hd)

    def read_body(self):
        if self.command in ("GET", "HEAD", "DELETE"):
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                self.rfile.read(min(n, 65536))
            return {}
        try:
            n = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise ApiError(411, "Content-Length obrigatório")
        if n > CONFIG["max_body_bytes"]:
            raise ApiError(413, "Requisição muito grande")
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "JSON inválido")
        if not isinstance(data, dict):
            raise ApiError(400, "JSON deve ser um objeto")
        return data

    def session_user(self):
        c = self.headers.get("Cookie", "")
        sid = ""
        for part in c.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "vigil_session":
                sid = v
        if not sid:
            return None
        u = db.one("SELECT u.id, u.org_id, u.username, u.role, s.csrf, s.id_hash AS session_hash FROM sessions s "
                   "JOIN users u ON u.id=s.user_id WHERE s.id_hash=? AND s.expires_at>?", (sha(sid), now()))
        return u

    def dispatch(self):
        self.extra_headers = []
        try:
            u = urlparse(self.path)
            path, self.query = u.path, parse_qs(u.query)
            for method, rx, fn, auth in ROUTES:
                if method != self.command:
                    continue
                m = rx.match(path)
                if not m:
                    continue
                body = self.read_body()
                if auth == "public":
                    ctx = None
                elif auth == "agent":
                    ctx = agent_auth(self)
                else:
                    ctx = self.session_user()
                    if not ctx:
                        raise ApiError(401, "Sessão expirada. Entre novamente.")
                    if self.command != "GET" and not hmac.compare_digest(self.headers.get("X-Vigil-CSRF", ""), ctx["csrf"]):
                        raise ApiError(403, "Falha de verificação (CSRF). Recarregue a página.")
                    if ROLES.get(ctx["role"], 0) < ROLES[auth]:
                        raise ApiError(403, "Seu perfil não tem permissão para esta ação")
                result = fn(self, m, ctx, body)
                return self.send_json(200, result)
            if self.command in ("GET", "HEAD"):
                return self.static(path)
            raise ApiError(404, "Rota não encontrada")
        except ApiError as e:
            self.send_json(e.status, {"error": e.msg}, e.headers)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, TimeoutError):
            pass
        except Exception:
            log.exception("Erro em %s %s", self.command, self.path)
            try:
                self.send_json(500, {"error": "Erro interno do servidor"})
            except Exception:
                pass

    def static(self, path):
        if path.startswith("/download/"):
            if not RL.allow(("dl", self.client_ip()), 120, 60):
                raise ApiError(429, "Muitos downloads. Aguarde.")
            parts = path.split("/")[2:]
            if len(parts) == 1 and parts[0] in ("vigil-agent-windows.zip", "vigil-agent-linux.zip"):
                plat = "windows" if "windows" in parts[0] else "linux"
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                    for name, rel in DOWNLOADS[plat].items():
                        z.writestr(f"vigil-agent-{plat}/{name}", read_agent_file(rel))
                return self.send(200, buf.getvalue(), "application/zip",
                                 {"Content-Disposition": f'attachment; filename="{parts[0]}"'})
            if len(parts) == 2 and parts[0] in DOWNLOADS and parts[1] in DOWNLOADS[parts[0]]:
                data = read_agent_file(DOWNLOADS[parts[0]][parts[1]])
                ctype = "text/plain; charset=utf-8"
                return self.send(200, data, ctype, {"Content-Disposition": f'attachment; filename="{parts[1]}"',
                                                    "Cache-Control": "no-store"})
            raise ApiError(404, "Arquivo não encontrado")
        if path in ("", "/"):
            path = "/index.html"
        full = os.path.normpath(os.path.join(WEB_DIR, path.lstrip("/")))
        if not full.startswith(os.path.normpath(WEB_DIR)) or not os.path.isfile(full):
            full = os.path.join(WEB_DIR, "index.html")
        with open(full, "rb") as f:
            data = f.read()
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        self.send(200, data, ctype, {"Cache-Control": "no-cache"})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = dispatch


class VigilServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128
    ssl_ctx = None

    def finish_request(self, request, client_address):
        # handshake TLS na thread da conexao (nao trava o accept em clientes lentos)
        request.settimeout(30)
        if self.ssl_ctx:
            try:
                request = self.ssl_ctx.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                request.close()
                return
        super().finish_request(request, client_address)


def main():
    global CONFIG, db
    setup_logging()
    CONFIG = load_config()
    if len(sys.argv) > 2 and sys.argv[1] == "--port":
        CONFIG["port"] = int(sys.argv[2])
    db = DB(DB_PATH)
    ensure_org()
    srv = VigilServer((CONFIG["host"], CONFIG["port"]), Handler)
    scheme = "http"
    if CONFIG["tls"]:
        cert, key = ensure_certificate()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        srv.ssl_ctx = ctx
        compute_cert_info(cert)
        scheme = "https"
    elif CONFIG["host"] not in ("127.0.0.1", "localhost", "::1"):
        log.warning("TLS DESATIVADO e servidor exposto na rede: use apenas atrás de um proxy HTTPS confiável!")
    stop = threading.Event()
    threading.Thread(target=monitor_loop, args=(stop,), daemon=True, name="monitor").start()
    log.info("VIGIL %s ouvindo em %s://%s:%s", VERSION, scheme, CONFIG["host"], CONFIG["port"])
    log.info("Painel: %s://localhost:%s  |  Endereço para agentes: %s", scheme, CONFIG["port"], public_url(ensure_org()))
    if CERT_INFO["fingerprint"]:
        log.info("Impressão digital (SHA-256) do certificado: %s", CERT_INFO["fingerprint"])
    if db.one("SELECT COUNT(*) n FROM users")["n"] == 0:
        log.info("Primeiro acesso: abra o painel NESTE computador para criar o administrador.")
    try:
        srv.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        srv.server_close()


if __name__ == "__main__":
    main()
