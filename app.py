"""
SyncPro – správa uživatelů UniFi Access
Jedna instance = jedna lokalita (škola). Vše se nastavuje v průvodci instalací
v prohlížeči: účet správce, adresa konzole, API token, volitelně WireGuard (wireproxy).
"""
import asyncio
import hashlib
import hmac
import json
import os
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import traceback
import urllib.request
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

BASE = Path(__file__).parent
APP_VERSION = os.environ.get("APP_VERSION", "dev")
APP_BUILD_DATE = os.environ.get("APP_BUILD_DATE", "")
GITHUB_REPO = "itsit-cz/UnifiAdminPro"
DATA = Path(os.environ.get("DATA_DIR", "/app/data"))
KEYS = Path(os.environ.get("KEYS_DIR", "/app/keys"))
WIREPROXY = os.environ.get("WIREPROXY_BIN", "wireproxy")
WG_PORT = int(os.environ.get("WG_PROXY_PORT", "25345"))
WG_INFO_PORT = WG_PORT + 1
CONFIG = DATA / "config.json"
AUDIT_FILE = DATA / "audit.jsonl"
DATA.mkdir(parents=True, exist_ok=True)
KEYS.mkdir(parents=True, exist_ok=True)


def _key(path: Path, gen) -> bytes:
    if not path.exists():
        path.write_bytes(gen())
        path.chmod(0o600)
    return path.read_bytes().strip()


fernet = Fernet(_key(KEYS / "master.key", Fernet.generate_key))
SESSION_SECRET = _key(KEYS / "session.key", lambda: secrets.token_urlsafe(48).encode()).decode()
enc = lambda s: fernet.encrypt(s.encode()).decode() if s else None
dec = lambda s: fernet.decrypt(s.encode()).decode() if s else None


# ---------------------------------------------------------------- konfigurace
def load_cfg() -> dict | None:
    if not CONFIG.exists():
        return None
    cfg = json.loads(CONFIG.read_text())
    if "admin" in cfg and "accounts" not in cfg:      # migrace z verze s jedním správcem
        cfg["accounts"] = [{**cfg.pop("admin"), "role": "admin", "allowed_roles": []}]
        save_cfg(cfg)
    return cfg


def get_account(cfg: dict | None, user: str | None) -> dict | None:
    return next((a for a in (cfg or {}).get("accounts", []) if a["user"] == user), None)


def mapped_roles(cfg: dict) -> list[dict]:
    """Role = skupiny z UniFi Access, které správce označil v Nastavení: [{group_id, name}]."""
    return cfg.get("roles", [])


def allowed_role_ids(cfg: dict, acc: dict) -> set[str]:
    ids = {r["group_id"] for r in mapped_roles(cfg)}
    return ids if acc.get("role") == "admin" else ids & set(acc.get("allowed_roles", []))


def save_cfg(cfg: dict):
    tmp = CONFIG.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    tmp.chmod(0o600)
    tmp.replace(CONFIG)


def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${h.hex()}"


def check_pw(pw: str, stored: str) -> bool:
    _, salt, h = stored.split("$")
    calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
    return hmac.compare_digest(calc.hex(), h)


SETUP_CODE = None
if not load_cfg():
    SETUP_CODE = f"{secrets.randbelow(10**6):06d}"
    print("=" * 60 + f"\n  SyncPro – INSTALAČNÍ KÓD: {SETUP_CODE}\n"
          "  Otevřete aplikaci v prohlížeči a zadejte tento kód.\n" + "=" * 60, flush=True)


def audit(who: str, action: str, detail: dict):
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "who": who, "action": action, **detail}
    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------- WireGuard (wireproxy)
WG_KEYS = {"interface": {"privatekey", "address", "dns", "mtu"},
           "peer": {"publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive"}}


def wireproxy_conf(text: str, tcp_tunnels: list[tuple[int, str]] | None = None) -> str:
    out, sec, seen, has_ka = [], None, set(), False
    for raw in text.splitlines():
        line = raw.split("#")[0].strip()
        if not line:
            continue
        if line.startswith("["):
            sec = line.strip("[]").strip().lower()
            if sec not in WG_KEYS or sec in seen:
                raise ValueError(f"Neplatná sekce [{sec}] – očekávám jedno [Interface] a jedno [Peer]")
            seen.add(sec)
            out += ["", f"[{sec.capitalize()}]"]
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if sec and k.lower() in WG_KEYS[sec] and v:
            has_ka |= k.lower() == "persistentkeepalive"
            out.append(f"{k} = {v}")
    if seen != {"interface", "peer"}:
        raise ValueError("Konfigurace WireGuard musí obsahovat [Interface] i [Peer]")
    if not has_ka:
        out.append("PersistentKeepalive = 25")
    out += ["", "[http]", f"BindAddress = 127.0.0.1:{WG_PORT}"]
    for port, target in tcp_tunnels or []:
        out += ["", "[TCPClientTunnel]", f"BindAddress = 127.0.0.1:{port}", f"Target = {target}"]
    return "\n".join(out).strip() + "\n"


def wg_endpoint(text: str | None) -> str | None:
    for line in (text or "").splitlines():
        if line.strip().lower().startswith("endpoint"):
            return line.split("=", 1)[1].strip()
    return None


class Tunnel:
    """wireproxy běží jako podproces; výstup jde do logu kontejneru a do bufferu pro UI."""

    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.conf: str | None = None
        self.path = Path(tempfile.gettempdir()) / "wireproxy.conf"
        self.log: deque[str] = deque(maxlen=60)

    def _pump(self, proc):
        for line in proc.stdout:
            line = line.rstrip()
            if not line or "Health metric request" in line:
                continue
            print(f"[wireproxy] {line}", flush=True)
            if "Routine:" not in line:
                self.log.append(line)

    def _spawn(self):
        self.proc = subprocess.Popen([WIREPROXY, "-c", str(self.path), "-i", f"127.0.0.1:{WG_INFO_PORT}"],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        threading.Thread(target=self._pump, args=(self.proc,), daemon=True).start()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def tail(self, n=6) -> str:
        return " | ".join(list(self.log)[-n:])

    async def start(self, wg_text: str, tcp_tunnels: list[tuple[int, str]] | None = None):
        self.stop()
        self.log.clear()
        self.conf = wireproxy_conf(wg_text, tcp_tunnels)
        self.path.write_text(self.conf)
        self.path.chmod(0o600)
        try:
            chk = subprocess.run([WIREPROXY, "-n", "-c", str(self.path)], capture_output=True, text=True, timeout=10)
        except FileNotFoundError:
            raise ValueError(f"Binárka wireproxy nenalezena ({WIREPROXY})")
        if chk.returncode != 0:
            raise ValueError("Neplatná konfigurace WireGuard: " + (chk.stderr or chk.stdout).strip()[-300:])
        self._spawn()
        for _ in range(50):
            if self.proc.poll() is not None:
                await asyncio.sleep(0.2)
                raise ValueError("wireproxy se ukončil hned po startu: " + self.tail())
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", WG_PORT)) == 0:
                    return
            await asyncio.sleep(0.2)
        raise ValueError("wireproxy nenaběhl: " + self.tail())

    async def ensure(self):
        if self.conf and not self.running:
            print("[wireproxy] proces neběží – restartuji", flush=True)
            self._spawn()
            await asyncio.sleep(1)

    def stats(self) -> dict:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{WG_INFO_PORT}/metrics", timeout=2) as r:
                kv = dict(l.split("=", 1) for l in r.read().decode().splitlines() if "=" in l)
            hs = int(kv.get("last_handshake_time_sec", 0))
            return {"handshake_age": int(time.time()) - hs if hs else None,
                    "rx_bytes": int(kv.get("rx_bytes", 0)), "tx_bytes": int(kv.get("tx_bytes", 0))}
        except Exception:  # noqa: BLE001
            return {"handshake_age": None, "rx_bytes": 0, "tx_bytes": 0}

    async def wait_handshake(self, timeout=10) -> dict:
        st = self.stats()
        for _ in range(timeout * 2):
            if st["handshake_age"] is not None:
                break
            await asyncio.sleep(0.5)
            st = self.stats()
        return st

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None


# ---------------------------------------------------------------- UniFi Access klient
class UAClient:
    def __init__(self):
        self.tunnel = Tunnel()
        self.client: httpx.AsyncClient | None = None
        self.pin: str | None = None
        self.last_error: str | None = None
        self.last_ok: float = 0.0

    async def configure(self, host: str, token: str, wg_text: str | None, pin: str | None,
                        tcp_tunnels: list[tuple[int, str]] | None = None):
        await self.close()
        proxy = None
        if wg_text:
            await self.tunnel.start(wg_text, tcp_tunnels)
            proxy = f"http://127.0.0.1:{WG_PORT}"
        # self-signed certifikát konzole: ověřujeme otisk (pinning) místo CA
        self.client = httpx.AsyncClient(
            base_url=f"{host.rstrip('/')}/api/v1/developer",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            verify=False, timeout=15, proxy=proxy)
        self.pin = pin

    async def close(self):
        if self.client:
            await self.client.aclose()
        self.client = None
        self.tunnel.stop()
        self.tunnel.conf = None

    @staticmethod
    def fingerprint(r: httpx.Response) -> str | None:
        stream = r.extensions.get("network_stream")
        so = stream.get_extra_info("ssl_object") if stream else None
        der = so.getpeercert(binary_form=True) if so else None
        return hashlib.sha256(der).hexdigest() if der else None

    async def request(self, method: str, path: str, raise_on_code: bool = True, **kw):
        if not self.client:
            raise HTTPException(503, "Připojení k UniFi Access není nastaveno")
        await self.tunnel.ensure()
        try:
            r = await self.client.request(method, path, **kw)
        except httpx.HTTPError as e:
            self.last_error = f"Konzole nedostupná ({type(e).__name__})"
            raise HTTPException(502, self.last_error + (" – zkontrolujte WireGuard tunel"
                                                        if self.tunnel.conf else ""))
        if self.pin:
            fp = self.fingerprint(r)
            if fp != self.pin:
                self.last_error = "Certifikát konzole se změnil!"
                raise HTTPException(495, "Certifikát konzole neodpovídá uloženému otisku. "
                                         "Pokud byl certifikát vyměněn, potvrďte nový v Nastavení.")
        try:
            body = r.json()
        except ValueError:
            raise HTTPException(502, f"Neočekávaná odpověď ({r.status_code})")
        code = body.get("code") if isinstance(body, dict) else None
        if method != "GET" or code != "SUCCESS":
            sent = kw.get("json")
            sent = {k: ("***" if "pin" in k else v) for k, v in sent.items()} if isinstance(sent, dict) else sent
            print(f"[ua] {method} {path} → HTTP {r.status_code} {code} {body.get('msg') if isinstance(body, dict) else ''}"
                  f"{' | body=' + json.dumps(sent, ensure_ascii=False)[:300] if sent is not None else ''}"
                  f"{' | data=' + json.dumps(body.get('data'), ensure_ascii=False)[:300] if method == 'POST' else ''}",
                  flush=True)
        if not raise_on_code and r.status_code < 500:
            return body
        if r.status_code >= 400 or body.get("code") != "SUCCESS":
            msg = f"{body.get('code')}: {body.get('msg')}"
            hints = {
                "CODE_USER_SSO_ACCOUNT_NAME_CANNOT_EDIT": "Uživatel je propojený s účtem UI (SSO) – jméno a příjmení "
                    "může změnit jen majitel účtu v UI Account Portalu (account.ui.com).",
            }
            if body.get("code") in hints:
                msg = hints[body["code"]] + f" ({body['code']})"
            if body.get("code") == "CODE_UNAUTHORIZED":
                msg += (" – API tokenu chybí oprávnění pro tuto akci (např. edit:user, edit:credential, "
                        "view:device). Vytvořte v Access nový token se všemi oprávněními.")
            raise HTTPException(r.status_code if r.status_code >= 400 else 400, msg)
        self.last_error = None
        self.last_ok = time.time()
        return body

    async def all_pages(self, path: str, params: dict | None = None):
        params, out, page = dict(params or {}), [], 1
        while True:
            params.update(page_num=page, page_size=100)
            body = await self.request("GET", path, params=params)
            data = body.get("data") or []
            out.extend(data)
            total = (body.get("pagination") or {}).get("total", len(out))
            if not data or len(out) >= total:
                return out
            page += 1


ua = UAClient()


AD_TUNNEL_PORT = WG_PORT + 2


def ad_tunnels(cfg: dict) -> list[tuple[int, str]]:
    """Přesměrování LDAP(S) na řadič domény ve škole přes WireGuard tunel."""
    ad = cfg.get("ad") or {}
    if ad.get("server") and cfg.get("wg_conf") and ad.get("via_tunnel", True):
        port = ad.get("port") or (636 if ad.get("mode", "ldaps") == "ldaps" else 389)
        out = [(AD_TUNNEL_PORT, f"{ad['server']}:{port}")]
        diag = 389 if port != 389 else 636          # druhý port jen pro diagnostiku (LDAP vs. LDAPS)
        out.append((AD_TUNNEL_PORT + 1, f"{ad['server']}:{diag}"))
        return out
    return []


async def apply_saved():
    cfg = load_cfg()
    if cfg and cfg.get("ua_host"):
        try:
            await ua.configure(cfg["ua_host"], dec(cfg["ua_token"]), dec(cfg.get("wg_conf")),
                               cfg.get("cert_sha256"), ad_tunnels(cfg))
        except Exception as e:  # noqa: BLE001
            ua.last_error = str(e)


# ---------------------------------------------------------------- aplikace + auth
app = FastAPI(title="SyncPro", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, max_age=8 * 3600,
                   same_site="strict", session_cookie="uap_session")


@app.on_event("startup")
async def _startup():
    await apply_saved()


@app.on_event("shutdown")
async def _shutdown():
    await ua.close()


def auth(request: Request) -> str:
    cfg = load_cfg()
    if not cfg:
        raise HTTPException(409, "Aplikace ještě není nainstalována")
    user = request.session.get("user")
    if not user or not get_account(cfg, user):
        request.session.clear()
        raise HTTPException(401, "Nepřihlášen")
    return user


def admin(who: str = Depends(auth)) -> str:
    if get_account(load_cfg(), who).get("role") != "admin":
        raise HTTPException(403, "Tuto akci smí provést jen správce")
    return who


# ---------------------------------------------------------------- členství v rolích (skupinách)
_members: dict = {"t": 0.0, "map": {}}


async def membership(force: bool = False) -> dict[str, str]:
    """user_id -> group_id pro namapované role (přímí členové skupin), cache 30 s."""
    if not force and time.time() - _members["t"] < 30:
        return _members["map"]
    m = {}
    for r in mapped_roles(load_cfg() or {}):
        try:
            data = (await ua.request("GET", f"/user_groups/{r['group_id']}/users"))["data"] or []
        except HTTPException as e:
            print(f"[roles] skupinu {r['name']} nelze načíst: {e.detail}", flush=True)
            continue
        for u in data:
            m.setdefault(u.get("id"), r["group_id"])
    _members.update(t=time.time(), map=m)
    return m


def invalidate_members():
    _members["t"] = 0.0


async def group_policy_ids(gids) -> dict[str, set[str]]:
    out = {}
    for gid in {g for g in gids if g}:
        try:
            out[gid] = {p.get("id") for p in (await ua.request("GET", f"/user_groups/{gid}/access_policies"))["data"] or []}
        except HTTPException:
            out[gid] = set()
    return out


async def own_policies(uid: str) -> list[dict]:
    """Politiky přiřazené přímo uživateli (bez zděděných ze skupiny)."""
    data = (await ua.request("GET", f"/users/{uid}/access_policies", params={"only_user_policies": "true"}))["data"]
    return [{"id": p.get("id"), "name": p.get("name")} for p in data or []]


async def clear_own_policies(uid: str) -> int:
    """Přístup jen přes roli: odebere uživateli přímo přiřazené politiky."""
    own = await own_policies(uid)
    if own:
        await ua.request("PUT", f"/users/{uid}/access_policies", json={"access_policy_ids": []})
    return len(own)


def can_manage(cfg: dict, acc: dict, role_id: str | None) -> bool:
    """Správce vše; operátor uživatele ve svých rolích, s volbou see_all i uživatele bez role."""
    if acc.get("role") == "admin":
        return True
    return role_id in allowed_role_ids(cfg, acc) or (acc.get("see_all") and not role_id)


def can_view(cfg: dict, acc: dict, role_id: str | None) -> bool:
    return can_manage(cfg, acc, role_id) or bool(acc.get("see_all"))


async def check_scope(who: str, uid: str, write: bool = True):
    """Operátor smí pracovat jen s uživateli ve svých rolích (see_all: vidí všechny, upravuje i bez role)."""
    cfg = load_cfg()
    acc = get_account(cfg, who)
    if acc.get("role") == "admin":
        return
    rid = (await membership()).get(uid)
    if not (can_manage if write else can_view)(cfg, acc, rid):
        raise HTTPException(403, "Tento uživatel nepatří do vašich rolí" + (" – můžete ho jen prohlížet" if can_view(cfg, acc, rid) else ""))


FAILS: dict[str, list[float]] = {}


def throttle(ip: str):
    now = time.time()
    FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < 300]
    if len(FAILS[ip]) >= 5:
        raise HTTPException(429, "Příliš mnoho pokusů, zkuste to za 5 minut")


# ---------------------------------------------------------------- stránky
def page(name):
    return FileResponse(BASE / "static" / name, headers={"Cache-Control": "no-store"})


@app.get("/")
async def index(request: Request):
    if not load_cfg():
        return RedirectResponse("/setup")
    if not request.session.get("user"):
        return RedirectResponse("/login")
    return page("index.html")


@app.get("/setup")
async def setup_page():
    return RedirectResponse("/") if load_cfg() else page("setup.html")


@app.get("/login")
async def login_page():
    return RedirectResponse("/setup") if not load_cfg() else page("login.html")


# ---------------------------------------------------------------- instalace
class ConnIn(BaseModel):
    ua_host: str
    ua_token: str = ""
    wg_mode: str = "none"        # none | replace | keep | remove
    wg_conf: str = ""
    setup_code: str = ""


class SetupIn(ConnIn):
    site_name: str
    admin_user: str
    admin_password: str
    cert_sha256: str


def resolve_conn(c: ConnIn, cfg: dict | None):
    host = c.ua_host.strip()
    if not host.startswith("https://"):
        host = "https://" + host
    if host.count(":") < 2:
        host += ":12445"
    token = c.ua_token.strip() or (dec(cfg["ua_token"]) if cfg else "")
    if not token:
        raise HTTPException(400, "Chybí API token")
    if c.wg_mode == "replace":
        wg = c.wg_conf.strip()
        try:
            wireproxy_conf(wg)
        except ValueError as e:
            raise HTTPException(400, str(e))
    elif c.wg_mode == "keep" and cfg:
        wg = dec(cfg.get("wg_conf"))
    else:
        wg = None
    return host, token, wg


async def test_conn(host, token, wg):
    steps = []
    try:
        await ua.configure(host, token, wg, None)
        if wg:
            ep = wg_endpoint(wg)
            steps.append({"ok": True, "text": "WireGuard klient spuštěn"})
            st = await ua.tunnel.wait_handshake(10)
            if st["handshake_age"] is None:
                steps.append({"ok": False, "text": f"UDM neodpověděl na WireGuard handshake (endpoint {ep}, UDP). "
                              "Zkontrolujte: veřejnou IP / DDNS v Endpoint, že škola není za CGNAT, "
                              "přesměrování UDP portu, že klient na UDM existuje (klíče sedí) a že síť serveru "
                              "pouští odchozí UDP."})
                return {"ok": False, "steps": steps, "wg_log": ua.tunnel.tail(10)}
            steps.append({"ok": True, "text": f"Handshake s UDM proběhl (endpoint {ep})"})
        r = await ua.client.get("/users", params={"page_num": 1, "page_size": 1})
        steps.append({"ok": True, "text": f"Konzole {host} odpovídá"})
        fp = ua.fingerprint(r)
        try:
            body = r.json()
        except ValueError:
            steps.append({"ok": False, "text": f"Na {host} neodpovídá UniFi Access API (HTTP {r.status_code}) – je to správná konzole?"})
            return {"ok": False, "steps": steps}
        if body.get("code") in ("CODE_ACCESS_TOKEN_INVALID", "CODE_AUTH_FAILED"):
            steps.append({"ok": False, "text": f"API token je neplatný nebo expirovaný ({body.get('code')}). "
                          "Je vytvořený v aplikaci Access na této konzoli?"})
            return {"ok": False, "steps": steps}
        # oprávnění tokenu – jen čtecí dotazy, nic se nemění
        now = int(time.time())
        checks = [
            ("Uživatelé – čtení (view:user)", "GET", "/users", {"params": {"page_num": 1, "page_size": 1}}, True),
            ("Přístupové politiky – čtení (view:policy)", "GET", "/access_policies", {}, True),
            ("Dveře – čtení (view:location)", "GET", "/doors", {}, False),
            ("Zařízení/čtečky – čtení (view:device)", "GET", "/devices", {}, False),
            ("Systémový log – čtení (view:system_log)", "POST", "/system/logs",
             {"params": {"page_num": 1, "page_size": 1},
              "json": {"topic": "door_openings", "since": now - 3600, "until": now}}, False),
        ]
        ok_all, users_total = True, None
        for label, method, path, kw, required in checks:
            try:
                b = (await ua.client.request(method, path, **kw)).json()
                code = b.get("code")
            except Exception as e:  # noqa: BLE001
                code = type(e).__name__
                b = {}
            good = code == "SUCCESS"
            if path == "/users" and good:
                users_total = (b.get("pagination") or {}).get("total")
            note = "" if good or required else (" (volitelné – nebude fungovat záložka Průchody)"
                                                if "logs" in path else " (volitelné)")
            steps.append({"ok": good, "text": f"{label}: {'OK' if good else code}{note}"})
            ok_all &= good or not required
        if not ok_all:
            steps.append({"ok": False, "text": "Tokenu chybí oprávnění. V Access → Settings → General → API Token "
                          "vytvořte nový a zaškrtněte u User a Access Policy čtení i zápis (View + Edit), "
                          "ideálně všechna oprávnění. Zápis (edit:user) nelze otestovat bez změny dat."})
            return {"ok": False, "steps": steps}
        return {"ok": True, "steps": steps, "cert_sha256": fp, "users_total": users_total}
    except ValueError as e:
        steps.append({"ok": False, "text": str(e)})
    except httpx.HTTPError as e:
        steps.append({"ok": False, "text": f"Konzole {host} nedostupná ({type(e).__name__}: {e})"
                      + (" – tunel je navázán, ale konzole přes něj neodpovídá: ověřte IP konzole a že VPN "
                         "klienti na UDM smí na TCP 12445" if wg else "")})
    except Exception as e:  # noqa: BLE001
        traceback.print_exc()
        steps.append({"ok": False, "text": f"Neočekávaná chyba: {type(e).__name__}: {e}"})
    finally:
        log = ua.tunnel.tail(10) if wg else None
        await apply_saved()
    return {"ok": False, "steps": steps, "wg_log": log}


def check_setup_code(code: str, ip: str):
    throttle(ip)
    if not SETUP_CODE or not hmac.compare_digest(code.strip(), SETUP_CODE):
        FAILS.setdefault(ip, []).append(time.time())
        raise HTTPException(403, "Neplatný instalační kód (najdete ho v logu kontejneru)")


@app.post("/api/setup/test")
async def setup_test(c: ConnIn, request: Request):
    if load_cfg():
        raise HTTPException(409, "Už nainstalováno")
    check_setup_code(c.setup_code, request.client.host)
    return await test_conn(*resolve_conn(c, None))


@app.post("/api/setup/complete")
async def setup_complete(s: SetupIn, request: Request):
    global SETUP_CODE
    if load_cfg():
        raise HTTPException(409, "Už nainstalováno")
    check_setup_code(s.setup_code, request.client.host)
    if len(s.admin_password) < 10:
        raise HTTPException(400, "Heslo musí mít alespoň 10 znaků")
    host, token, wg = resolve_conn(s, None)
    save_cfg({"site_name": s.site_name.strip(),
              "accounts": [{"user": s.admin_user.strip(), "pw": hash_pw(s.admin_password), "role": "admin",
                            "allowed_roles": []}],
              "roles": [], "ua_host": host, "ua_token": enc(token),
              "wg_conf": enc(wg), "cert_sha256": s.cert_sha256 or None,
              "installed": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    SETUP_CODE = None
    await apply_saved()
    request.session["user"] = s.admin_user.strip()
    audit(s.admin_user, "install", {"ua_host": host, "wireguard": bool(wg)})
    return {"ok": True}


# ---------------------------------------------------------------- přihlášení
class LoginIn(BaseModel):
    user: str
    password: str


@app.post("/api/login")
async def login(li: LoginIn, request: Request):
    ip = request.client.host
    throttle(ip)
    acc = get_account(load_cfg(), li.user.strip()) or {}
    if not check_pw(li.password, acc.get("pw", "x$00$00")):
        FAILS.setdefault(ip, []).append(time.time())
        raise HTTPException(401, "Neplatné jméno nebo heslo")
    request.session["user"] = acc["user"]
    return {"ok": True}


@app.post("/api/logout")
async def logout(request: Request):
    request.session.clear()
    return {"ok": True}


# ---------------------------------------------------------------- nastavení
_health_task: asyncio.Task | None = None


async def _ua_check():
    try:
        await asyncio.wait_for(ua.request("GET", "/users", params={"page_num": 1, "page_size": 1}), 15)
    except Exception as e:  # noqa: BLE001
        if not ua.last_error:
            ua.last_error = getattr(e, "detail", None) or f"{type(e).__name__}"


async def ua_health() -> dict:
    """Stav napojení na UniFi Access – při stáří > 60 s se ověří na pozadí (stav neblokuje)."""
    global _health_task
    if ua.client and time.time() - ua.last_ok > 60 and (_health_task is None or _health_task.done()):
        _health_task = asyncio.get_running_loop().create_task(_ua_check())
    age = int(time.time() - ua.last_ok) if ua.last_ok else None
    return {"ua_ok": bool(ua.last_ok) and age is not None and age < 120 and not ua.last_error, "ua_ok_age": age}


@app.get("/api/status")
async def status(who: str = Depends(auth)):
    cfg = load_cfg()
    acc = get_account(cfg, who)
    wg = dec(cfg.get("wg_conf"))
    base = {"user": who, "account_role": acc.get("role"), "see_all": bool(acc.get("see_all")),
            "site_name": cfg.get("site_name"),
            "roles": [r for r in mapped_roles(cfg) if r["group_id"] in allowed_role_ids(cfg, acc)]}
    base.update(await ua_health())
    if acc.get("role") != "admin":
        return {**base, "wireguard": bool(wg), "tunnel_up": ua.tunnel.running,
                **(ua.tunnel.stats() if wg else {}), "last_error": ua.last_error}
    return {**base, "ua_host": cfg.get("ua_host"),
            "wireguard": bool(wg), "wg_endpoint": wg_endpoint(wg), "tunnel_up": ua.tunnel.running,
            **(ua.tunnel.stats() if wg else {}),
            "cert_sha256": cfg.get("cert_sha256"), "last_error": ua.last_error}


class SaveConnIn(ConnIn):
    cert_sha256: str


@app.post("/api/settings/test")
async def settings_test(c: ConnIn, who: str = Depends(admin)):
    return await test_conn(*resolve_conn(c, load_cfg()))


@app.post("/api/settings/connection")
async def settings_save(c: SaveConnIn, who: str = Depends(admin)):
    cfg = load_cfg()
    host, token, wg = resolve_conn(c, cfg)
    cfg.update(ua_host=host, ua_token=enc(token), wg_conf=enc(wg), cert_sha256=c.cert_sha256 or None)
    save_cfg(cfg)
    await apply_saved()
    audit(who, "settings", {"ua_host": host, "wireguard": bool(wg), "token_changed": bool(c.ua_token)})
    return {"ok": True}


class PwIn(BaseModel):
    old: str
    new: str


@app.post("/api/settings/password")
async def settings_pw(p: PwIn, who: str = Depends(auth)):
    cfg = load_cfg()
    acc = get_account(cfg, who)
    if not check_pw(p.old, acc["pw"]):
        raise HTTPException(400, "Původní heslo nesouhlasí")
    if len(p.new) < 10:
        raise HTTPException(400, "Heslo musí mít alespoň 10 znaků")
    acc["pw"] = hash_pw(p.new)
    save_cfg(cfg)
    audit(who, "password", {})
    return {"ok": True}


# ---------------------------------------------------------------- UniFi Access API
class NewUser(BaseModel):
    first_name: str
    last_name: str
    user_email: str | None = None
    employee_number: str | None = None
    role_id: str | None = None
    pin_code: str | None = None


class RoleIn(BaseModel):
    role_id: str


class StatusIn(BaseModel):
    status: str


class PoliciesIn(BaseModel):
    access_policy_ids: list[str]


class PinIn(BaseModel):
    pin_code: str


@app.get("/api/users")
async def users(who: str = Depends(auth)):
    cfg = load_cfg()
    acc = get_account(cfg, who)
    allowed = allowed_role_ids(cfg, acc)
    m = await membership(force=True)
    gp = await group_policy_ids(set(m.values()))
    out = []
    for u in await ua.all_pages("/users", {"expand[]": "access_policy"}):
        u["role_id"] = m.get(u.get("id"))
        inherited = gp.get(u["role_id"], set())
        u["own_policies"] = [{"id": p.get("id"), "name": p.get("name")}
                             for p in u.get("access_policies") or [] if p.get("id") not in inherited]
        if can_view(cfg, acc, u["role_id"]):
            u["can_manage"] = can_manage(cfg, acc, u["role_id"])
            out.append(u)
    return out


@app.get("/api/policies")
async def policies(_: str = Depends(auth)):
    return (await ua.request("GET", "/access_policies"))["data"]


@app.post("/api/users")
async def create_user(u: NewUser, who: str = Depends(auth)):
    cfg = load_cfg()
    acc = get_account(cfg, who)
    if u.pin_code and (not u.pin_code.isdigit() or not 4 <= len(u.pin_code) <= 8):
        raise HTTPException(400, "PIN musí mít 4–8 číslic")
    if mapped_roles(cfg) or acc.get("role") != "admin":
        if not u.role_id:
            raise HTTPException(400, "Vyberte roli")
        if u.role_id not in allowed_role_ids(cfg, acc):
            raise HTTPException(403, "Do této role nemůžete zakládat uživatele")
    body = {k: v for k, v in u.model_dump(include={"first_name", "last_name", "user_email",
                                                    "employee_number"}).items() if v}
    body["onboard_time"] = int(time.time())
    created = (await ua.request("POST", "/users", json=body))["data"]
    uid = created["id"]
    if u.role_id:
        await ua.request("POST", f"/user_groups/{u.role_id}/users", json=[uid])
        invalidate_members()
        try:   # výchozí politika UniFi Access se novému uživateli přiřadí automaticky – přístup jen přes roli
            await clear_own_policies(uid)
        except HTTPException as e:
            print(f"[roles] nelze odebrat výchozí politiku novému uživateli: {e.detail}", flush=True)
    if u.pin_code:
        await ua.request("PUT", f"/users/{uid}/pin_codes", json={"pin_code": u.pin_code})
    audit(who, "create", {"user_id": uid, "name": f"{u.first_name} {u.last_name}",
                          "role": role_name(cfg, u.role_id), "pin": bool(u.pin_code)})
    return created


def role_name(cfg: dict, gid: str | None) -> str | None:
    return next((r["name"] for r in mapped_roles(cfg) if r["group_id"] == gid), gid)


@app.put("/api/users/{uid}/role")
async def set_role(uid: str, r: RoleIn, who: str = Depends(auth)):
    cfg = load_cfg()
    acc = get_account(cfg, who)
    await check_scope(who, uid)
    if r.role_id not in allowed_role_ids(cfg, acc):
        raise HTTPException(403, "Do této role nemůžete uživatele přesunout")
    old = (await membership(force=True)).get(uid)
    if old != r.role_id:
        await ua.request("POST", f"/user_groups/{r.role_id}/users", json=[uid])
        if old:
            await ua.request("POST", f"/user_groups/{old}/users/delete", json=[uid])
        invalidate_members()
    try:   # přístup jen přes roli – pokus o úklid přímo přiřazených politik, chyba nesmí zablokovat změnu role
        await clear_own_policies(uid)
    except HTTPException as e:
        print(f"[roles] vlastní politiky uživatele {uid} nelze odebrat: {e.detail}", flush=True)
    audit(who, "role", {"user_id": uid, "from": role_name(cfg, old), "to": role_name(cfg, r.role_id)})
    return {"ok": True}


@app.post("/api/maintenance/clear-own-policies")
async def bulk_clear_own(who: str = Depends(admin)):
    """Všem uživatelům s rolí odebere přímo přiřazené politiky (přístup jen přes roli)."""
    m = await membership(force=True)
    done, failed = 0, []
    for uid in m:
        try:
            if await clear_own_policies(uid):
                done += 1
        except HTTPException as e:
            failed.append(f"{uid}: {e.detail}")
    audit(who, "clear_own_policies", {"users": done, "failed": len(failed)})
    return {"ok": True, "cleared": done, "failed": failed[:10]}


@app.put("/api/users/{uid}/status")
async def set_status(uid: str, s: StatusIn, who: str = Depends(auth)):
    await check_scope(who, uid)
    if s.status not in ("ACTIVE", "DEACTIVATED"):
        raise HTTPException(400, "Status musí být ACTIVE nebo DEACTIVATED")
    await ua.request("PUT", f"/users/{uid}", json={"status": s.status})
    audit(who, "status", {"user_id": uid, "status": s.status})
    return {"ok": True}


@app.put("/api/users/{uid}/policies")
async def set_policies(uid: str, p: PoliciesIn, who: str = Depends(admin)):
    await ua.request("PUT", f"/users/{uid}/access_policies",
                     json={"access_policy_ids": p.access_policy_ids})
    audit(who, "policies", {"user_id": uid, "policies": p.access_policy_ids})
    return {"ok": True}


@app.put("/api/users/{uid}/pin")
async def set_pin(uid: str, p: PinIn, who: str = Depends(auth)):
    await check_scope(who, uid)
    if not p.pin_code.isdigit() or not 4 <= len(p.pin_code) <= 8:
        raise HTTPException(400, "PIN musí mít 4–8 číslic")
    await ua.request("PUT", f"/users/{uid}/pin_codes", json={"pin_code": p.pin_code})
    audit(who, "pin", {"user_id": uid})
    return {"ok": True}


@app.delete("/api/users/{uid}")
async def delete_user(uid: str, who: str = Depends(admin)):
    await ua.request("PUT", f"/users/{uid}", json={"status": "DEACTIVATED"})
    await ua.request("DELETE", f"/users/{uid}")
    invalidate_members()
    audit(who, "delete", {"user_id": uid})
    return {"ok": True}




# ---------------------------------------------------------------- role (mapování skupin)
class RoleMapIn(BaseModel):
    group_id: str
    name: str


@app.get("/api/groups")
async def groups(_: str = Depends(admin)):
    """Všechny skupiny z UniFi Access + zda jsou namapované jako role + jejich politiky."""
    cfg = load_cfg()
    mapped = {r["group_id"]: r["name"] for r in mapped_roles(cfg)}
    data = (await ua.request("GET", "/user_groups"))["data"] or []
    out = []
    for g in data:
        try:
            pol = (await ua.request("GET", f"/user_groups/{g['id']}/access_policies"))["data"] or []
        except HTTPException:
            pol = []
        out.append({"id": g["id"], "name": g.get("full_name") or g.get("name"), "role": g["id"] in mapped,
                    "role_name": mapped.get(g["id"]) or g.get("name"), "policies": [x.get("name") for x in pol]})
    return out


@app.get("/api/roles")
async def roles(who: str = Depends(auth)):
    cfg = load_cfg()
    acc = get_account(cfg, who)
    out, allowed = [], allowed_role_ids(cfg, acc)
    for r in mapped_roles(cfg):
        if r["group_id"] not in allowed and not acc.get("see_all"):
            continue
        try:
            pol = (await ua.request("GET", f"/user_groups/{r['group_id']}/access_policies"))["data"] or []
        except HTTPException:
            pol = []
        out.append({**r, "policies": [x.get("name") for x in pol], "allowed": r["group_id"] in allowed})
    return out


@app.put("/api/roles")
async def roles_save(items: list[RoleMapIn], who: str = Depends(admin)):
    cfg = load_cfg()
    cfg["roles"] = [{"group_id": i.group_id, "name": i.name.strip() or i.group_id} for i in items]
    ids = {i.group_id for i in items}
    for a in cfg["accounts"]:               # odebrat operátorům zrušené role
        a["allowed_roles"] = [x for x in a.get("allowed_roles", []) if x in ids]
    save_cfg(cfg)
    invalidate_members()
    audit(who, "roles", {"roles": ", ".join(r["name"] for r in cfg["roles"])})
    return {"ok": True}


# ---------------------------------------------------------------- účty aplikace
class AccountIn(BaseModel):
    user: str
    password: str = ""
    role: str = "operator"          # admin | operator
    allowed_roles: list[str] = []
    name: str = ""
    ua_user_id: str | None = None   # propojení s uživatelem z UniFi Access
    see_all: bool = False           # operátor vidí všechny uživatele (i bez role)


def _acc_public(a: dict) -> dict:
    return {"user": a["user"], "name": a.get("name", ""), "role": a.get("role"),
            "allowed_roles": a.get("allowed_roles", []), "ua_user_id": a.get("ua_user_id"),
            "see_all": bool(a.get("see_all"))}


@app.get("/api/accounts")
async def accounts_list(_: str = Depends(admin)):
    return [_acc_public(a) for a in load_cfg()["accounts"]]


@app.post("/api/accounts")
async def accounts_save(a: AccountIn, who: str = Depends(admin)):
    cfg = load_cfg()
    user = a.user.strip()
    if not user or any(ch.isspace() for ch in user):
        raise HTTPException(400, "Neplatné uživatelské jméno")
    if a.role not in ("admin", "operator"):
        raise HTTPException(400, "Neplatná role účtu")
    ids = {r["group_id"] for r in mapped_roles(cfg)}
    allowed = [x for x in a.allowed_roles if x in ids]
    acc = get_account(cfg, user)
    if a.ua_user_id:
        other = next((x for x in cfg["accounts"] if x.get("ua_user_id") == a.ua_user_id and x["user"] != user), None)
        if other:
            raise HTTPException(400, f"Tento uživatel už má účet „{other['user']}“")
    if a.password and len(a.password) < 10:
        raise HTTPException(400, "Heslo musí mít alespoň 10 znaků")
    if acc is None:
        if not a.password:
            raise HTTPException(400, "Zadejte heslo nového účtu")
        if a.role == "operator" and not allowed:
            raise HTTPException(400, "Operátor musí mít povolenou alespoň jednu roli")
        cfg["accounts"].append({"user": user, "pw": hash_pw(a.password), "role": a.role,
                                "allowed_roles": allowed, "name": a.name.strip(), "ua_user_id": a.ua_user_id,
                                "see_all": a.see_all and a.role == "operator"})
        action = "account_create"
    else:
        if user == who and a.role != "admin":
            raise HTTPException(400, "Sami sobě nemůžete odebrat roli správce")
        acc.update(role=a.role, allowed_roles=allowed, name=a.name.strip(), see_all=a.see_all and a.role == "operator")
        if a.ua_user_id:
            acc["ua_user_id"] = a.ua_user_id
        if a.password:
            acc["pw"] = hash_pw(a.password)
        action = "account_edit"
    save_cfg(cfg)
    audit(who, action, {"account": user, "role": a.role, "password_changed": bool(a.password),
                        **({"user_id": a.ua_user_id} if a.ua_user_id else {})})
    return {"ok": True}


@app.delete("/api/accounts/{user}")
async def accounts_delete(user: str, who: str = Depends(admin)):
    cfg = load_cfg()
    if user == who:
        raise HTTPException(400, "Nemůžete smazat vlastní účet")
    if not get_account(cfg, user):
        raise HTTPException(404, "Účet neexistuje")
    cfg["accounts"] = [a for a in cfg["accounts"] if a["user"] != user]
    save_cfg(cfg)
    audit(who, "account_delete", {"account": user})
    return {"ok": True}



# ---------------------------------------------------------------- Edookit
# Protokol podle dosavadního synchronizačního nástroje školy (SyncLibrary.EdookitService):
#  * Osobní údaje studentů: GET /api/student-data/v1/list, HTTP Basic (jméno/heslo k osobním údajům),
#    odpověď {"Students": [...]} s poli vybranými v API modulu (Firstname, Lastname, PersonId, ClassName…).
#  * API Docházka: GET /api/dochazka/v2/zaci | tridy | klas-skupiny, podepsané hlavičky:
#      com.edookit.Client = Code
#      com.edookit.Time   = místní čas "yyyy-MM-dd HH:mm:ss.fff"
#      com.edookit.Auth   = Sign + ":" + hex(HMAC-SHA1(key=Client, msg=METHOD + "+/" + cesta + "+" + čas + "+" + Password))
import hmac as _hmac
from zoneinfo import ZoneInfo

EDOOKIT_TZ = ZoneInfo(os.environ.get("EDOOKIT_TZ", "Europe/Prague"))
EDOOKIT_SENSITIVE = {"personalnumber", "idcardnumber", "passportnumber", "healthinsurancecompanycode",
                     "rodnecislo", "birthnumber", "identityhash"}
EK_KNOWN = [("/api/student-data/v1/list", "basic", "Osobní údaje studentů"),
            ("/api/dochazka/v2/zaci", "hmac", "Žáci (API Docházka)"),
            ("/api/dochazka/v2/tridy", "hmac", "Třídy (API Docházka)"),
            ("/api/dochazka/v2/klas-skupiny", "hmac", "Skupiny (API Docházka)")]


class EdookitCfgIn(BaseModel):
    url: str
    username: str = ""          # osobní údaje (Basic)
    password: str = ""
    client: str = ""            # API Docházka (HMAC)
    sign: str = ""
    code: str = ""
    api_password: str = ""


class EdookitProbeIn(BaseModel):
    path: str | None = None     # vlastní cesta; bez ní se zkouší známé endpointy
    method: str = "GET"


class EdookitSourceIn(BaseModel):
    path: str
    method: str = "GET"
    auth: str = "basic"         # basic | hmac


def ek_cfg() -> dict:
    return (load_cfg() or {}).get("edookit") or {}


def ek_has(c: dict, auth: str) -> bool:
    if auth == "basic":
        return bool(c.get("username") and c.get("password"))
    if auth == "hmac":
        return all(c.get(k) for k in ("client", "sign", "code", "api_password"))
    return True


def ek_hmac_headers(c: dict, method: str, path: str) -> dict:
    t = datetime.now(EDOOKIT_TZ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    msg = f"{method.upper()}+/{path.lstrip('/')}+{t}+{dec(c['api_password'])}"
    digest = _hmac.new(dec(c["client"]).encode("ascii"), msg.encode("ascii"), hashlib.sha1).hexdigest()
    return {"com.edookit.Client": dec(c["code"]), "com.edookit.Auth": f"{dec(c['sign'])}:{digest}",
            "com.edookit.Time": t}


async def ek_request(path: str, method: str = "GET", auth: str = "basic", timeout: int = 30) -> httpx.Response:
    c = ek_cfg()
    if not c.get("url"):
        raise HTTPException(400, "Edookit není nastaven (Nastavení → Edookit)")
    if not ek_has(c, auth):
        raise HTTPException(400, "Chybí přístupové údaje pro " + ("osobní údaje" if auth == "basic" else "API Docházka"))
    path = "/" + path.lstrip("/")
    headers = {"Accept": "application/json"}
    kw: dict = {}
    if auth == "basic":
        kw["auth"] = (c["username"], dec(c["password"]))
    elif auth == "hmac":
        headers.update(ek_hmac_headers(c, method, path))
    async with httpx.AsyncClient(base_url=c["url"].rstrip("/"), timeout=timeout, follow_redirects=False,
                                 headers=headers) as cl:
        return await cl.request(method, path, **kw)


def ek_find_list(data):
    """Najde v odpovědi seznam záznamů (list slovníků) – přímo, nebo v poli objektu (např. Students)."""
    if isinstance(data, list) and (not data or isinstance(data[0], dict)):
        return data
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, list) and (not v or isinstance(v[0], dict)):
                return v
        for v in data.values():
            if isinstance(v, dict):
                r = ek_find_list(v)
                if r is not None:
                    return r
    return None


def ek_secrets(c: dict) -> list[str]:
    return [x for x in (dec(c.get(k)) for k in ("password", "client", "sign", "api_password")) if x]


def ek_mask(text: str) -> str:
    for sec in ek_secrets(ek_cfg()):
        text = text.replace(sec, "***")
    return text


def ek_scrub(row: dict) -> dict:
    return {k: ("•••" if k.lower() in EDOOKIT_SENSITIVE else v) for k, v in row.items()}


@app.get("/api/edookit/config")
async def ek_config_get(_: str = Depends(admin)):
    c = ek_cfg()
    return {"url": c.get("url", ""), "username": c.get("username", ""), "has_password": bool(c.get("password")),
            "has_hmac": ek_has(c, "hmac"), "hmac_set": {k: bool(c.get(k)) for k in ("client", "sign", "code", "api_password")},
            "source": c.get("source")}


@app.post("/api/edookit/config")
async def ek_config_save(e: EdookitCfgIn, who: str = Depends(admin)):
    cfg = load_cfg()
    old = cfg.get("edookit") or {}
    url = e.url.strip().rstrip("/")
    if url and not url.startswith("http"):
        url = "https://" + url
    if not url.startswith("https://"):
        raise HTTPException(400, "Zadejte adresu instance, např. https://skola.edookit.net")
    new = {**old, "url": url, "username": e.username.strip()}
    for field, val in (("password", e.password), ("client", e.client), ("sign", e.sign), ("code", e.code),
                       ("api_password", e.api_password)):
        if val.strip():
            new[field] = enc(val.strip())
    new.pop("module", None)
    cfg["edookit"] = new
    save_cfg(cfg)
    _ek_cache.update(t=0.0, data=None)
    audit(who, "edookit_config", {"url": url, "basic": ek_has(new, "basic"), "hmac": ek_has(new, "hmac")})
    return {"ok": True}


async def ek_try(path: str, method: str, auth: str, label: str = "") -> dict:
    out = {"path": path, "method": method, "auth": auth, "label": label}
    try:
        r = await ek_request(path, method, auth, timeout=30)
    except HTTPException as e:
        return {**out, "status": None, "error": e.detail}
    except httpx.HTTPError as e:
        return {**out, "status": None, "error": type(e).__name__}
    ct = r.headers.get("content-type", "")
    out.update(status=r.status_code, content_type=ct.split(";")[0], size=len(r.content),
               location=r.headers.get("location"), www_authenticate=r.headers.get("www-authenticate"))
    try:
        data = r.json()
        lst = ek_find_list(data)
        if lst is not None:
            out["items"] = len(lst)
            out["keys"] = sorted({k for row in lst[:50] for k in row})
            data = {"…": f"{len(lst)} záznamů", "ukázka": [ek_scrub(x) for x in lst[:2]]}
        out["sample"] = ek_mask(json.dumps(data, ensure_ascii=False)[:1200])
    except ValueError:
        out["sample"] = ek_mask(r.text[:400])
    return out


@app.post("/api/edookit/probe")
async def ek_probe(p: EdookitProbeIn, who: str = Depends(admin)):
    c = ek_cfg()
    if p.path:
        auths = [a for a in ("basic", "hmac") if ek_has(c, a)] or ["none"]
        res = [await ek_try(p.path.strip(), p.method.upper(), a, "vlastní cesta") for a in auths]
    else:
        res = [await ek_try(path, "GET", auth, label) if ek_has(c, auth) else
               {"path": path, "method": "GET", "auth": auth, "label": label, "status": None,
                "error": "nevyplněné přístupové údaje"} for path, auth, label in EK_KNOWN]
    print("[edookit] test: " + ", ".join(f"{x['path']}={x['status']}" for x in res), flush=True)
    return {"results": res}


@app.post("/api/edookit/source")
async def ek_source_save(src: EdookitSourceIn, who: str = Depends(admin)):
    cfg = load_cfg()
    cfg.setdefault("edookit", {})["source"] = {"path": src.path, "method": src.method.upper(), "auth": src.auth}
    save_cfg(cfg)
    audit(who, "edookit_source", {"path": src.path, "auth": src.auth})
    return {"ok": True}


def ek_pick(row: dict, *names):
    low = {k.lower(): v for k, v in row.items()}
    for n in names:
        if n in low and low[n] not in (None, "", []):
            v = low[n]
            return ", ".join(map(str, v)) if isinstance(v, list) else v
    return None


_ek_cache: dict = {"t": 0.0, "data": None}


async def ek_fetch_list(path: str, auth: str) -> list:
    r = await ek_request(path, "GET", auth, timeout=120)
    if r.status_code != 200:
        raise HTTPException(502, f"Edookit vrátil HTTP {r.status_code} pro {path}")
    try:
        lst = ek_find_list(r.json())
    except ValueError:
        raise HTTPException(502, f"Edookit nevrátil JSON pro {path}")
    if lst is None:
        raise HTTPException(502, f"V odpovědi {path} není seznam záznamů")
    return lst


async def ek_load(force: bool = False) -> dict:
    """Studenti = osobní údaje (aktuální studenti), doplnění z API Docházka (e-mail, karta, třída).
    Bez osobních údajů se použijí žáci z API Docházka. Drží se jen v paměti (5 min)."""
    if not force and _ek_cache["data"] and time.time() - _ek_cache["t"] < 300:
        return _ek_cache["data"]
    c = ek_cfg()
    if not (ek_has(c, "basic") or ek_has(c, "hmac")):
        raise HTTPException(409, "Edookit není nastaven – vyplňte přístupové údaje v Nastavení → Edookit")
    jobs = {}
    if ek_has(c, "basic"):
        jobs["personal"] = ek_fetch_list("/api/student-data/v1/list", "basic")
    if ek_has(c, "hmac"):
        jobs["zaci"] = ek_fetch_list("/api/dochazka/v2/zaci", "hmac")
        jobs["tridy"] = ek_fetch_list("/api/dochazka/v2/tridy", "hmac")
        jobs["skupiny"] = ek_fetch_list("/api/dochazka/v2/klas-skupiny", "hmac")
    res = dict(zip(jobs, await asyncio.gather(*jobs.values(), return_exceptions=True)))
    warnings = []
    for k, v in list(res.items()):
        if isinstance(v, Exception):
            warnings.append(f"{k}: {getattr(v, 'detail', None) or type(v).__name__}")
            res[k] = None
    personal, zaci, tridy = res.get("personal"), res.get("zaci"), res.get("tridy")
    if personal is None and zaci is None:
        raise HTTPException(502, "Edookit: nepodařilo se načíst studenty – " + "; ".join(warnings))
    tmap = {t.get("PkTrida"): t for t in tridy or []}
    # Klasifikační skupiny (např. 1A1, 1A2): [{PkKlasSkupina, Zkratka, EvSkupina, Zaci: [{PkZak}…]}].
    # Starý sync bral zkratku skupiny jako „studijní skupinu“ studenta (přepíše třídu).
    gmap, by_zak = {}, {}
    for g in res.get("skupiny") or []:
        gid = g.get("PkKlasSkupina")
        if gid is None:
            continue
        members = [(m.get("PkZak") if isinstance(m, dict) else m) for m in (g.get("Zaci") or [])]
        gmap[gid] = {**{k: v for k, v in g.items() if k != "Zaci"}, "PocetZaku": len(members)}
        for zid in members:
            if zid is not None:
                by_zak.setdefault(zid, []).append(gid)
    zmap = {z.get("PkZak"): z for z in zaci or []}
    pmap = {}
    rows = []

    def make(pid, p, z):
        t = tmap.get((z or {}).get("PkTrida"))
        gids = by_zak.get(pid, [])
        groups = sorted({str(gmap[g].get("Zkratka")) for g in gids if gmap[g].get("Zkratka")})
        klass = (p or {}).get("ClassName") or (t or {}).get("Zkratka")
        roc = (t or {}).get("Rocnik")
        if roc in (None, ""):
            first = next((x for x in [*groups, klass] if x and str(x)[0].isdigit()), None)
            roc = int(str(first)[0]) if first else None
        return {
            "groups": groups, "year": roc,
            "id": pid,
            "first_name": (p or {}).get("Firstname") or (z or {}).get("Jmeno"),
            "last_name": (p or {}).get("Lastname") or (z or {}).get("Prijmeni"),
            "class": klass,
            "email": (z or {}).get("Email") or (p or {}).get("Email"),
            "card": (z or {}).get("Karta"),
            "card_number": (z or {}).get("KartaCislo"),
            "active": (z or {}).get("AktivniEvidence") if z else (True if p else None),
            "in_personal": p is not None, "in_zaci": z is not None,
        }

    if personal is not None:
        for p in personal:
            pid = p.get("PersonId")
            pmap[pid] = p
            rows.append(make(pid, p, zmap.get(pid)))
    else:
        for z in zaci:
            rows.append(make(z.get("PkZak"), None, z))
    data = {"rows": rows, "personal": pmap, "zaci": zmap, "tridy": tmap, "skupiny": gmap, "by_zak": by_zak,
            "warnings": warnings,
            "sources": [k for k in ("personal", "zaci", "tridy", "skupiny") if res.get(k) is not None],
            "loaded": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    _ek_cache.update(t=time.time(), data=data)
    print(f"[edookit] načteno studentů: {len(rows)} (zdroje: {', '.join(data['sources'])}"
          f"{'; varování: ' + '; '.join(warnings) if warnings else ''})", flush=True)
    return data


@app.get("/api/edookit/students")
async def ek_students(refresh: bool = False, _: str = Depends(admin)):
    d = await ek_load(force=refresh)
    return {"count": len(d["rows"]), "sources": d["sources"], "warnings": d["warnings"], "loaded": d["loaded"],
            "students": d["rows"]}


@app.get("/api/edookit/students/{sid}")
async def ek_student(sid: str, _: str = Depends(admin)):
    d = await ek_load()
    key = next((k for k in list(d["personal"]) + list(d["zaci"]) if str(k) == sid), None)
    if key is None:
        raise HTTPException(404, "Student nenalezen (zkuste načíst seznam znovu)")
    p, z = d["personal"].get(key), d["zaci"].get(key)
    t = d["tridy"].get((z or {}).get("PkTrida"))
    return {"id": key, "sections": [
        {"title": "Osobní údaje studentů (/api/student-data/v1/list)", "data": ek_scrub(p) if p else None},
        {"title": "API Docházka – žák (/api/dochazka/v2/zaci)", "data": ek_scrub(z) if z else None},
        {"title": "API Docházka – třída (/api/dochazka/v2/tridy)", "data": t},
        {"title": "API Docházka – skupiny žáka (/api/dochazka/v2/klas-skupiny)",
         "data": {str(d["skupiny"][g].get("Zkratka") or g): d["skupiny"][g] for g in d["by_zak"].get(key, [])} or None},
    ]}



# ---------------------------------------------------------------- Active Directory (on-premise, LDAP)
# Školní AD (např. vossp.cze). Čtení přes LDAP(S) účtem jen pro čtení; řadič domény je ve škole,
# proto spojení vede přes WireGuard tunel (wireproxy TCPClientTunnel na 127.0.0.1:AD_TUNNEL_PORT).
import ssl as _ssl
import ldap3
from ldap3.utils.conv import escape_filter_chars

AD_HIDDEN = {"identityhash", "unicodepwd", "userpassword", "ntpwdhistory", "lmpwdhistory", "dbcspwd",
             "supplementalcredentials", "msds-keycredentiallink", "msds-managedpassword", "msmcsadmpwd",
             "ms-mcs-admpwd", "msds-supportedencryptiontypes"}
AD_LIST_ATTRS = ["sAMAccountName", "userPrincipalName", "givenName", "sn", "displayName", "mail", "department",
                 "title", "memberOf", "userAccountControl", "otherPager", "edookitPersonID", "employeeID",
                 "employeeNumber", "whenCreated", "lastLogonTimestamp"]
AD_DEFAULTS = {"students_dn": "OU=Students,OU=Accounts,DC=vossp,DC=cze",
               "classes_dn": "OU=StudentsClasses,OU=Students,OU=Accounts,DC=vossp,DC=cze",
               "employees_dn": "", "exclude_dn": "OU=DEL,OU=Students,OU=Accounts,DC=vossp,DC=cze", "mode": "ldaps"}
_ad_cache: dict = {}


class AdCfgIn(BaseModel):
    server: str
    port: int | None = None
    mode: str = "ldaps"              # ldaps | starttls | plain
    via_tunnel: bool = True
    bind_user: str = ""
    bind_password: str = ""
    students_dn: str = ""
    classes_dn: str = ""
    employees_dn: str = ""
    exclude_dn: str = ""             # např. OU=DEL (vyřazení) – volitelné vyloučení ze seznamu studentů


def ad_cfg() -> dict:
    return {**AD_DEFAULTS, **((load_cfg() or {}).get("ad") or {})}


def ad_val(v):
    if isinstance(v, (bytes, bytearray)):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return v.hex()
    if isinstance(v, datetime):
        return v.isoformat()
    return v


def ad_attrs(entry: dict) -> dict:
    raw = entry.get("raw_attributes") or {}
    out = {}
    for k, vals in raw.items():
        if k.lower() in AD_HIDDEN or not vals:
            continue
        if k.lower() == "objectguid" and vals:
            import uuid as _uuid
            out[k] = str(_uuid.UUID(bytes_le=bytes(vals[0])))
            continue
        if k.lower() == "objectsid" and vals:
            b = bytes(vals[0])
            try:
                sub = [int.from_bytes(b[8 + 4 * i:12 + 4 * i], "little") for i in range(b[1])]
                out[k] = f"S-{b[0]}-{int.from_bytes(b[2:8], 'big')}-" + "-".join(map(str, sub))
            except Exception:  # noqa: BLE001
                out[k] = b.hex()
            continue
        vv = [ad_val(x) for x in vals]
        out[k] = vv[0] if len(vv) == 1 else vv
    return out


def ad_filetime(v) -> str | None:
    try:
        n = int(v)
        if n <= 0 or n >= 0x7FFFFFFFFFFFFFFF:
            return None
        return datetime.fromtimestamp(n / 1e7 - 11644473600, timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError):
        return None


def card_swap(v: str | None) -> str | None:
    """Edookit ↔ AD otherPager: obrácené pořadí dvojic znaků (12345678 ↔ 78563412)."""
    if not v:
        return None
    v = str(v)
    pairs = [v[i:i + 2] for i in range(0, len(v), 2)]
    return "".join(reversed(pairs))


def ad_connect(c: dict | None = None) -> ldap3.Connection:
    c = c or ad_cfg()
    if not c.get("server"):
        raise HTTPException(409, "Active Directory není nastaveno (Nastavení → Active Directory)")
    mode = c.get("mode", "ldaps")
    port = c.get("port") or (636 if mode == "ldaps" else 389)
    host = c["server"]
    tunneled = bool(ad_tunnels(load_cfg() or {}))
    if tunneled:
        host, port = "127.0.0.1", AD_TUNNEL_PORT
    tls = ldap3.Tls(validate=_ssl.CERT_NONE) if mode in ("ldaps", "starttls") else None
    server = ldap3.Server(host, port=port, use_ssl=(mode == "ldaps"), tls=tls, get_info=ldap3.NONE, connect_timeout=10)
    conn = ldap3.Connection(server, user=c.get("bind_user") or None, password=dec(c.get("bind_password")) or None,
                            authentication=ldap3.SIMPLE, receive_timeout=60, raise_exceptions=False, auto_referrals=False)
    try:
        try:
            opened = conn.open()
            why = conn.last_error
        except Exception as e:  # noqa: BLE001
            opened, why = False, f"{type(e).__name__}: {e}"
        if not opened:
            raise HTTPException(502, f"Řadič domény nedostupný ({host}:{port}{' přes tunel' if tunneled else ''})"
                                     + (f" – {why}" if why else ""))
        if mode == "starttls" and not conn.start_tls():
            raise HTTPException(502, f"StartTLS selhal: {conn.result.get('description')}")
        if not conn.bind():
            r = conn.result or {}
            msg = r.get("message") or r.get("description")
            hint = (" – zkontrolujte jméno (např. svc@vossp.cze) a heslo" if r.get("result") == 49 else
                    " – řadič vyžaduje zabezpečené spojení, použijte LDAPS" if r.get("result") == 8 else "")
            raise HTTPException(502, f"Přihlášení do AD selhalo: {msg}{hint}")
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Spojení s AD selhalo: {type(e).__name__}: {e}")
    return conn


def ad_search(conn: ldap3.Connection, base: str, flt: str, attrs, scope=ldap3.SUBTREE) -> list[dict]:
    res = conn.extend.standard.paged_search(base, flt, search_scope=scope, attributes=attrs, paged_size=500,
                                            generator=False)
    if conn.result and conn.result.get("result") not in (0, None):
        raise HTTPException(502, f"Hledání v AD ({base}) selhalo: {conn.result.get('description')} {conn.result.get('message', '')}")
    return [e for e in res if e.get("type") == "searchResEntry"]


def ad_row(e: dict, classes_dn: str) -> dict:
    a = ad_attrs(e)
    lk = {k.lower(): v for k, v in a.items()}
    groups = lk.get("memberof") or []
    groups = [groups] if isinstance(groups, str) else groups
    cn = lambda dn: dn.split(",", 1)[0].split("=", 1)[-1]
    cls = [cn(g) for g in groups if classes_dn and g.lower().endswith(classes_dn.lower())]
    uac = int(lk.get("useraccountcontrol") or 0)
    dn = e.get("dn", "")
    card = lk.get("otherpager")
    card = (card[0] if card else None) if isinstance(card, list) else card
    return {
        "dn": dn, "login": lk.get("samaccountname"), "upn": lk.get("userprincipalname"),
        "first_name": lk.get("givenname"), "last_name": lk.get("sn"),
        "name": lk.get("displayname") or " ".join(x for x in (lk.get("givenname"), lk.get("sn")) if x),
        "email": lk.get("mail"), "department": lk.get("department"), "title": lk.get("title"),
        "class": ", ".join(cls) or None, "groups": [cn(g) for g in groups],
        "card_ad": card, "card_edookit": card_swap(card), "edookit_id": lk.get("edookitpersonid"),
        "enabled": not (uac & 2), "ou": dn.split(",", 1)[1] if "," in dn else "",
        "last_logon": ad_filetime(lk.get("lastlogontimestamp")),
    }


@app.get("/api/ad/config")
async def ad_config_get(_: str = Depends(admin)):
    c = ad_cfg()
    return {k: c.get(k) for k in ("server", "port", "mode", "via_tunnel", "bind_user", "students_dn", "classes_dn",
                                  "employees_dn", "exclude_dn")} | {"has_password": bool(c.get("bind_password")),
                                                                    "wireguard": bool((load_cfg() or {}).get("wg_conf"))}


@app.post("/api/ad/config")
async def ad_config_save(a: AdCfgIn, who: str = Depends(admin)):
    cfg = load_cfg()
    old = cfg.get("ad") or {}
    if a.mode not in ("ldaps", "starttls", "plain"):
        raise HTTPException(400, "Neplatný režim spojení")
    new = {"server": a.server.strip(), "port": a.port or None, "mode": a.mode, "via_tunnel": a.via_tunnel,
           "bind_user": a.bind_user.strip(), "students_dn": a.students_dn.strip(), "classes_dn": a.classes_dn.strip(),
           "employees_dn": a.employees_dn.strip(), "exclude_dn": a.exclude_dn.strip(),
           "bind_password": enc(a.bind_password) if a.bind_password else old.get("bind_password")}
    tunnels_changed = ad_tunnels({**cfg, "ad": new}) != ad_tunnels(cfg)
    cfg["ad"] = new
    save_cfg(cfg)
    _ad_cache.clear()
    if tunnels_changed:
        await apply_saved()          # restart tunelu s přesměrováním na řadič domény
    audit(who, "ad_config", {"server": new["server"], "mode": a.mode, "tunnel": bool(ad_tunnels(cfg))})
    return {"ok": True, "tunnel_restarted": tunnels_changed}


def ad_port_probe(host: str, port: int, tls: bool, timeout: float = 8) -> tuple[bool, str]:
    """Zjistí, zda na portu odpovídá LDAP (bez TLS) nebo LDAPS (TLS handshake)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return False, f"nelze se připojit ({e.strerror or e})"
    try:
        sock.settimeout(timeout)
        if tls:
            ctx = _ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, _ssl.CERT_NONE
            with ctx.wrap_socket(sock) as ss:
                cert = ss.getpeercert(binary_form=True)
                return True, f"LDAPS odpovídá (TLS {ss.version()}, certifikát {len(cert or b'')} B)"
        # LDAP rootDSE: anonymní search request (BER), stačí jakákoli odpověď
        req = bytes.fromhex("3025020101632004000a01000a0100020100020100010100870b6f626a656374636c6173733000")
        sock.sendall(req)
        data = sock.recv(64)
        return (True, "LDAP odpovídá") if data[:1] == b"\x30" else (False, "spojení navázáno, ale nepřišla odpověď LDAP")
    except _ssl.SSLError as e:
        return False, f"TLS handshake selhal ({e.reason or e}) – port pravděpodobně nemá LDAPS"
    except (ConnectionResetError, BrokenPipeError):
        return False, "spojení ukončeno – cíl odmítl spojení nebo je nedostupný"
    except socket.timeout:
        return False, "žádná odpověď (timeout)"
    except OSError as e:
        return False, f"chyba: {e}"
    finally:
        try:
            sock.close()
        except OSError:
            pass


def ad_diagnose(c: dict) -> list[dict]:
    steps = []
    cfg = load_cfg() or {}
    tun = ad_tunnels(cfg)
    server = c.get("server")
    if tun:
        if not ua.tunnel.running:
            return [{"ok": False, "text": "WireGuard tunel neběží – zkontrolujte připojení v Nastavení"}]
        import ipaddress
        allowed = []
        for line in (dec(cfg.get("wg_conf")) or "").splitlines():
            if line.strip().lower().startswith("allowedips"):
                allowed += [x.strip() for x in line.split("=", 1)[1].split(",") if x.strip()]
        try:
            ip = ipaddress.ip_address(server)
            if allowed and not any(ip in ipaddress.ip_network(a, strict=False) for a in allowed):
                steps.append({"ok": False, "text": f"AllowedIPs ve WireGuard konfigurace SyncPro ({', '.join(allowed)}) neobsahují "
                              f"{server} – provoz na řadič nejde do tunelu. Na UDM upravte klienta / stáhněte konfiguraci "
                              f"s touto sítí a nahrajte ji v Nastavení, nebo přidejte síť do AllowedIPs."})
        except ValueError:
            pass
        for (lport, target) in tun:
            port = int(target.rsplit(":", 1)[1])
            ok, msg = ad_port_probe("127.0.0.1", lport, tls=(port == 636))
            steps.append({"ok": ok, "text": f"{target} přes tunel: {msg}"})
        log = [l for l in ua.tunnel.log if server in l and "TCP Client Tunnel" in l][-4:]
        for l in log:
            port = l.split(server + ":", 1)[-1].split(":", 1)[0]
            why = ("řadič spojení odmítl – na tomto portu nic neposlouchá" if "refused" in l else
                   "řadič neodpovídá – IP neexistuje nebo spojení blokuje firewall" if ("timeout" in l or "timed out" in l
                                                                                     or "unreachable" in l or "no route" in l) else l)
            steps.append({"ok": False, "text": f"WireGuard klient → {server}:{port}: {why}"})
    else:
        port = c.get("port") or (636 if c.get("mode", "ldaps") == "ldaps" else 389)
        ok, msg = ad_port_probe(server, port, tls=(c.get("mode", "ldaps") == "ldaps"))
        steps.append({"ok": ok, "text": f"{server}:{port}: {msg}"})
    states = {int(x["text"].split(":")[1].split(" ")[0]): x["ok"] for x in steps if x["ok"] is not None and ":" in x["text"]}
    if states.get(636) is False and states.get(389):
        steps.append({"ok": None, "text": "👉 Řadič odpovídá na 389, ale ne na 636: nemá LDAPS certifikát. Přepněte Zabezpečení na "
                                          "StartTLS (389); pokud ani to nepůjde, je potřeba řadiči vystavit certifikát (AD CS)."})
    elif states and not any(states.values()):
        steps.append({"ok": None, "text": "👉 Řadič neodpovídá na žádném portu: ověřte IP adresu a že firewall UDM pouští VPN "
                                          "klienty do sítě řadiče (TCP 389/636)."})
    return steps


@app.post("/api/ad/test")
async def ad_test(_: str = Depends(admin)):
    c = ad_cfg()

    def run_test():
        steps = []
        conn = ad_connect(c)
        steps.append({"ok": True, "text": f"Přihlášení jako {c.get('bind_user') or '(anonymně)'} proběhlo"})
        conn.search("", "(objectClass=*)", search_scope=ldap3.BASE, attributes=["defaultNamingContext", "dnsHostName"])
        if conn.entries:
            info = ad_attrs(conn.response[0])
            steps.append({"ok": True, "text": f"Řadič domény: {info.get('dnsHostName', '?')}, doména {info.get('defaultNamingContext', '?')}"})
        for label, key in (("Studenti", "students_dn"), ("Třídy (skupiny)", "classes_dn"), ("Zaměstnanci", "employees_dn")):
            base = c.get(key)
            if not base:
                steps.append({"ok": None, "text": f"{label}: OU není nastavena"})
                continue
            try:
                flt = "(objectClass=group)" if key == "classes_dn" else "(&(objectCategory=person)(objectClass=user))"
                n = len(ad_search(conn, base, flt, ["cn"]))
                steps.append({"ok": True, "text": f"{label}: {n} objektů v {base}"})
            except HTTPException as e:
                steps.append({"ok": False, "text": f"{label}: {e.detail}"})
        conn.unbind()
        return steps

    try:
        steps = await asyncio.to_thread(run_test)
    except HTTPException as e:
        diag = await asyncio.to_thread(ad_diagnose, c)
        return {"ok": False, "steps": [{"ok": False, "text": e.detail}] + diag}
    return {"ok": all(x["ok"] is not False for x in steps), "steps": steps}


@app.get("/api/ad/ous")
async def ad_ous(_: str = Depends(admin)):
    """Organizační jednotky domény – pro výběr OU studentů a zaměstnanců."""
    def run():
        conn = ad_connect()
        conn.search("", "(objectClass=*)", search_scope=ldap3.BASE, attributes=["defaultNamingContext"])
        base = ad_attrs(conn.response[0]).get("defaultNamingContext") if conn.response else None
        if not base:
            raise HTTPException(502, "Nelze zjistit kořen domény")
        ous = ad_search(conn, base, "(objectClass=organizationalUnit)", ["ou"])
        conn.unbind()
        return sorted((e["dn"] for e in ous), key=lambda d: list(reversed(d.lower().split(","))))
    return await asyncio.to_thread(run)


@app.get("/api/ad/users")
async def ad_users(kind: str = "students", refresh: bool = False, _: str = Depends(admin)):
    if kind not in ("students", "employees"):
        raise HTTPException(400, "kind musí být students nebo employees")
    c = ad_cfg()
    base = c.get("students_dn" if kind == "students" else "employees_dn")
    if not base:
        raise HTTPException(409, f"OU {'studentů' if kind == 'students' else 'zaměstnanců'} není nastavena "
                                 "(Nastavení → Active Directory)")
    hit = _ad_cache.get(kind)
    if hit and not refresh and time.time() - hit["t"] < 300:
        return hit["data"]

    def run():
        conn = ad_connect(c)
        entries = ad_search(conn, base, "(&(objectCategory=person)(objectClass=user))", AD_LIST_ATTRS)
        conn.unbind()
        return entries

    entries = await asyncio.to_thread(run)
    excl = (c.get("exclude_dn") or "").lower()
    rows = [ad_row(e, c.get("classes_dn", "")) for e in entries]
    for r in rows:
        r["excluded_ou"] = bool(excl and r["dn"].lower().endswith(excl))
    data = {"count": len(rows), "base": base, "loaded": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "users": rows}
    _ad_cache[kind] = {"t": time.time(), "data": data}
    print(f"[ad] načteno {kind}: {len(rows)} z {base}", flush=True)
    return data


@app.get("/api/ad/user")
async def ad_user(dn: str, _: str = Depends(admin)):
    c = ad_cfg()
    bases = [b.lower() for b in (c.get("students_dn"), c.get("employees_dn")) if b]
    if not any(dn.lower().endswith(b) for b in bases):
        raise HTTPException(403, "Uživatel je mimo nastavené OU")

    def run():
        conn = ad_connect(c)
        conn.search(dn, "(objectClass=*)", search_scope=ldap3.BASE, attributes=[ldap3.ALL_ATTRIBUTES])
        res = conn.response[0] if conn.response else None
        conn.unbind()
        return res

    e = await asyncio.to_thread(run)
    if not e or e.get("type") != "searchResEntry":
        raise HTTPException(404, "Uživatel nenalezen")
    a = ad_attrs(e)
    for k in list(a):
        if k.lower() in ("lastlogontimestamp", "lastlogon", "pwdlastset", "accountexpires", "badpasswordtime",
                         "lastlogoff", "lockouttime"):
            a[k] = ad_filetime(a[k]) or a[k]
    row = ad_row(e, c.get("classes_dn", ""))
    return {"dn": dn, "summary": row, "attributes": dict(sorted(a.items(), key=lambda kv: kv[0].lower()))}


# ---------------------------------------------------------------- detail a úprava uživatele
class UserEditIn(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    user_email: str | None = None
    employee_number: str | None = None


class CardIn(BaseModel):
    token: str
    force_add: bool = False


class PlateIn(BaseModel):
    plate: str


class EnrollIn(BaseModel):
    device_id: str
    reset_ua_card: bool = False


def norm_plate(p: str) -> str:
    return "".join(ch for ch in p.upper() if ch.isalnum())


@app.get("/api/users/{uid}")
async def get_user(uid: str, who: str = Depends(auth)):
    await check_scope(who, uid, write=False)
    cfg = load_cfg()
    u = (await ua.request("GET", f"/users/{uid}", params={"expand[]": "access_policy"}))["data"]
    u["role_id"] = (await membership()).get(uid)
    u["can_manage"] = can_manage(cfg, get_account(cfg, who), u["role_id"])
    try:
        u["own_policies"] = await own_policies(uid)
    except HTTPException:     # starší UniFi Access bez only_user_policies – odhad z politik role
        inh = (await group_policy_ids([u["role_id"]])).get(u["role_id"], set())
        u["own_policies"] = [{"id": p.get("id"), "name": p.get("name")}
                             for p in u.get("access_policies") or [] if p.get("id") not in inh]
    return u


@app.put("/api/users/{uid}")
async def edit_user(uid: str, u: UserEditIn, who: str = Depends(auth)):
    await check_scope(who, uid)
    # posílat jen změněná pole – u SSO uživatelů nelze měnit jméno a odeslání beze změny by selhalo
    body = {k: v.strip() for k, v in u.model_dump().items() if v is not None}
    if "first_name" in body and not body["first_name"] or "last_name" in body and not body["last_name"]:
        raise HTTPException(400, "Jméno a příjmení nesmí být prázdné")
    if not body:
        return {"ok": True}
    await ua.request("PUT", f"/users/{uid}", json=body)
    audit(who, "edit", {"user_id": uid, "fields": ", ".join(body)})
    return {"ok": True}


@app.delete("/api/users/{uid}/pin")
async def remove_pin(uid: str, who: str = Depends(auth)):
    await check_scope(who, uid)
    await ua.request("DELETE", f"/users/{uid}/pin_codes")
    audit(who, "pin_remove", {"user_id": uid})
    return {"ok": True}


@app.put("/api/users/{uid}/cards")
async def add_card(uid: str, c: CardIn, who: str = Depends(auth)):
    await check_scope(who, uid)
    token = c.token.strip()
    if not token:
        raise HTTPException(400, "Chybí token karty")
    await ua.request("PUT", f"/users/{uid}/nfc_cards", json={"token": token, "force_add": c.force_add})
    audit(who, "card_add", {"user_id": uid, "card": token[-6:]})
    return {"ok": True}


@app.post("/api/users/{uid}/cards/remove")
async def remove_card(uid: str, c: CardIn, who: str = Depends(auth)):
    await check_scope(who, uid)
    await ua.request("PUT", f"/users/{uid}/nfc_cards/delete", json={"token": c.token})
    audit(who, "card_remove", {"user_id": uid, "card": c.token[-6:]})
    return {"ok": True}


@app.post("/api/users/{uid}/plates")
async def add_plate(uid: str, p: PlateIn, who: str = Depends(auth)):
    await check_scope(who, uid)
    plate = norm_plate(p.plate)
    if not 2 <= len(plate) <= 12:
        raise HTTPException(400, "Neplatná SPZ")
    # API přijímá holé pole řetězců (UniFi Access 3.3.10+)
    await ua.request("PUT", f"/users/{uid}/license_plates", json=[plate])
    audit(who, "plate_add", {"user_id": uid, "plate": plate})
    return {"ok": True, "plate": plate}


@app.delete("/api/users/{uid}/plates/{pid}")
async def remove_plate(uid: str, pid: str, plate: str = "", who: str = Depends(auth)):
    await check_scope(who, uid)
    await ua.request("DELETE", f"/users/{uid}/license_plates/{pid}")
    audit(who, "plate_remove", {"user_id": uid, "plate": plate or pid})
    return {"ok": True}


# ---------------------------------------------------------------- čtečky a načtení karty
def _flatten(data):
    for x in data or []:
        if isinstance(x, list):
            yield from _flatten(x)
        elif isinstance(x, dict):
            yield x


@app.get("/api/devices")
async def devices(_: str = Depends(auth)):
    data = (await ua.request("GET", "/devices"))["data"]
    out = [{"id": d.get("id"), "name": d.get("alias") or d.get("name") or d.get("id"),
            "type": d.get("type") or d.get("device_type") or ""} for d in _flatten(data)]
    # čtečky (UA-G2, UA-G3, Reader, Ultra, Intercom) napřed
    rd = lambda d: 0 if any(k in d["type"].upper() for k in ("G2", "G3", "READER", "ULTRA", "INTERCOM", "LITE")) else 1
    return sorted(out, key=lambda d: (rd(d), d["name"]))


@app.post("/api/enroll")
async def enroll_start(e: EnrollIn, _: str = Depends(auth)):
    data = (await ua.request("POST", "/credentials/nfc_cards/sessions",
                             json={"device_id": e.device_id, "reset_ua_card": e.reset_ua_card}))["data"]
    return {"session_id": data.get("session_id")}


@app.get("/api/enroll/{sid}")
async def enroll_poll(sid: str, _: str = Depends(auth)):
    body = await ua.request("GET", f"/credentials/nfc_cards/sessions/{sid}", raise_on_code=False)
    code, data = body.get("code"), body.get("data") or {}
    if code == "SUCCESS" and data.get("token"):
        return {"done": True, "token": data["token"], "card_id": data.get("card_id") or data.get("display_id")}
    if code in ("SUCCESS", "CODE_CREDS_NFC_READ_POLL_TOKEN_EMPTY"):
        return {"done": False}
    hints = {"CODE_CREDS_NFC_CARD_IS_PROVISION": "Karta je registrovaná na jiném místě – zaškrtněte „Resetovat kartu z jiného místa“.",
             "CODE_CREDS_NFC_CARD_PROVISION_FAILED": "Držte kartu u čtečky déle než 5 sekund.",
             "CODE_CREDS_NFC_CARD_INVALID": "Nepodporovaný typ karty (použijte UA Card, nebo povolte karty třetích stran).",
             "CODE_CREDS_NFC_READ_SESSION_NOT_FOUND": "Relace načítání vypršela, zkuste to znovu."}
    raise HTTPException(400, hints.get(code, f"{code}: {body.get('msg')}"))


@app.delete("/api/enroll/{sid}")
async def enroll_cancel(sid: str, _: str = Depends(auth)):
    await ua.request("DELETE", f"/credentials/nfc_cards/sessions/{sid}", raise_on_code=False)
    return {"ok": True}


# ---------------------------------------------------------------- verze a aktualizace
_latest: dict = {"t": 0.0, "data": None}


async def latest_build() -> dict | None:
    """Poslední úspěšně sestavený image = poslední úspěšný běh workflow na main."""
    if _latest["data"] and time.time() - _latest["t"] < 600:
        return _latest["data"]
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"https://api.github.com/repos/{GITHUB_REPO}/actions/runs",
                            params={"branch": "main", "status": "success", "per_page": 1},
                            headers={"Accept": "application/vnd.github+json"})
            run = r.json()["workflow_runs"][0]
        _latest.update(t=time.time(), data={"sha": run["head_sha"], "title": run.get("display_title"),
                                            "date": run.get("updated_at")})
    except Exception as e:  # noqa: BLE001
        print(f"[update] nelze zjistit nejnovější verzi: {e}", flush=True)
    return _latest["data"]


@app.get("/api/version")
async def version(refresh: bool = False, _: str = Depends(auth)):
    if refresh:
        _latest["t"] = 0
    lb = await latest_build()
    upd = (load_cfg() or {}).get("updater") or {}
    return {"current": APP_VERSION[:7], "current_full": APP_VERSION, "build_date": APP_BUILD_DATE,
            "latest": lb["sha"][:7] if lb else None, "latest_title": lb and lb["title"],
            "latest_date": lb and lb["date"],
            "update_available": bool(lb and APP_VERSION != "dev" and lb["sha"] != APP_VERSION),
            "updater": upd.get("method")}


class UpdaterIn(BaseModel):
    method: str                 # portainer | webhook | none
    url: str = ""
    token: str = ""
    stack_id: int | None = None
    webhook: str = ""


async def portainer_stack(url: str, token: str, sid: int) -> dict:
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        r = await c.get(f"{url.rstrip('/')}/api/stacks/{sid}", headers={"X-API-Key": token})
    if r.status_code == 401:
        raise HTTPException(400, "Portainer odmítl přístupový token")
    if r.status_code == 404:
        raise HTTPException(400, f"Stack {sid} v Portaineru neexistuje")
    if r.status_code >= 400:
        raise HTTPException(400, f"Portainer: HTTP {r.status_code} {r.text[:150]}")
    return r.json()


@app.get("/api/update/config")
async def updater_get(_: str = Depends(admin)):
    u = (load_cfg() or {}).get("updater") or {}
    return {"method": u.get("method", "none"), "url": u.get("url", ""), "stack_id": u.get("stack_id"),
            "has_token": bool(u.get("token")), "has_webhook": bool(u.get("webhook"))}


@app.post("/api/update/config")
async def updater_save(u: UpdaterIn, who: str = Depends(admin)):
    cfg = load_cfg()
    old = cfg.get("updater") or {}
    if u.method == "portainer":
        token = u.token.strip() or dec(old.get("token")) or ""
        if not (u.url.startswith("http") and token and u.stack_id):
            raise HTTPException(400, "Vyplňte adresu Portaineru, přístupový token a ID stacku")
        st = await portainer_stack(u.url, token, u.stack_id)
        new = {"method": "portainer", "url": u.url.rstrip("/"), "token": enc(token), "stack_id": u.stack_id}
        info = f"Stack „{st.get('Name')}“ nalezen" + (" (Git)" if st.get("GitConfig") else "")
    elif u.method == "webhook":
        hook = u.webhook.strip() or dec(old.get("webhook")) or ""
        if "/api/stacks/webhooks/" not in hook:
            raise HTTPException(400, "Očekávám URL ve tvaru https://portainer…/api/stacks/webhooks/<id>")
        new, info = {"method": "webhook", "webhook": enc(hook)}, "Webhook uložen"
    else:
        new, info = {"method": "none"}, "Aktualizace z webu vypnuta"
    cfg["updater"] = new
    save_cfg(cfg)
    audit(who, "updater", {"method": u.method})
    return {"ok": True, "info": info}


async def _do_update(u: dict):
    try:
        if u["method"] == "webhook":
            async with httpx.AsyncClient(verify=False, timeout=60) as c:
                r = await c.post(dec(u["webhook"]))
            print(f"[update] webhook HTTP {r.status_code}", flush=True)
            return
        token = dec(u["token"])
        st = await portainer_stack(u["url"], token, u["stack_id"])
        ep = st.get("EndpointId")
        async with httpx.AsyncClient(verify=False, timeout=300, headers={"X-API-Key": token}) as c:
            if st.get("GitConfig"):
                r = await c.put(f"{u['url']}/api/stacks/{u['stack_id']}/git/redeploy", params={"endpointId": ep},
                                json={"Env": st.get("Env") or [], "Prune": False, "PullImage": True,
                                      "RepullImageAndRedeploy": True})
            else:
                f = (await c.get(f"{u['url']}/api/stacks/{u['stack_id']}/file")).json()
                r = await c.put(f"{u['url']}/api/stacks/{u['stack_id']}", params={"endpointId": ep},
                                json={"StackFileContent": f.get("StackFileContent"), "Env": st.get("Env") or [],
                                      "Prune": False, "PullImage": True})
        print(f"[update] Portainer redeploy HTTP {r.status_code} {r.text[:200]}", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"[update] chyba: {type(e).__name__}: {e}", flush=True)


@app.post("/api/update/run")
async def update_run(who: str = Depends(admin)):
    u = (load_cfg() or {}).get("updater") or {}
    if u.get("method") not in ("portainer", "webhook"):
        raise HTTPException(400, "Aktualizace z webu není nastavena")
    audit(who, "update", {"from": APP_VERSION[:7], "method": u["method"]})
    asyncio.get_running_loop().create_task(_do_update(u))
    return {"ok": True, "from": APP_VERSION[:7]}


@app.get("/api/logs")
async def logs(hours: int = 24, user_id: str | None = None, who: str = Depends(auth)):
    cfg = load_cfg()
    acc = get_account(cfg, who)
    if user_id:
        await check_scope(who, user_id, write=False)
    now = int(time.time())
    body = {"topic": "door_openings", "since": now - hours * 3600, "until": now}
    if user_id:
        body["actor_id"] = user_id
    data = (await ua.request("POST", "/system/logs", params={"page_num": 1, "page_size": 200},
                             json=body))["data"] or {}
    out = []
    for h in data.get("hits", []):
        s = h.get("_source", h)
        ev, actor = s.get("event", {}), s.get("actor", {})
        door = next((t.get("display_name") for t in s.get("target", []) if t.get("type") == "door"), None)
        out.append({"time": h.get("@timestamp") or ev.get("published"), "user": actor.get("display_name"),
                    "user_id": actor.get("id"), "door": door, "result": ev.get("result"),
                    "method": (s.get("authentication") or {}).get("credential_provider")})
    if acc.get("role") != "admin" and not acc.get("see_all"):
        m, allowed = await membership(), allowed_role_ids(cfg, acc)
        out = [x for x in out if m.get(x["user_id"]) in allowed]
    return out


@app.get("/api/audit")
async def audit_log(limit: int = 200, _: str = Depends(admin)):
    if not AUDIT_FILE.exists():
        return []
    lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()[-limit:]
    return [json.loads(line) for line in reversed(lines)]


app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
