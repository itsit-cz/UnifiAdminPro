"""
UnifiAdminPro – správa uživatelů UniFi Access
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
    print("=" * 60 + f"\n  UnifiAdminPro – INSTALAČNÍ KÓD: {SETUP_CODE}\n"
          "  Otevřete aplikaci v prohlížeči a zadejte tento kód.\n" + "=" * 60, flush=True)


def audit(who: str, action: str, detail: dict):
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "who": who, "action": action, **detail}
    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------- WireGuard (wireproxy)
WG_KEYS = {"interface": {"privatekey", "address", "dns", "mtu"},
           "peer": {"publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive"}}


def wireproxy_conf(text: str) -> str:
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

    async def start(self, wg_text: str):
        self.stop()
        self.log.clear()
        self.conf = wireproxy_conf(wg_text)
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

    async def configure(self, host: str, token: str, wg_text: str | None, pin: str | None):
        await self.close()
        proxy = None
        if wg_text:
            await self.tunnel.start(wg_text)
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


async def apply_saved():
    cfg = load_cfg()
    if cfg and cfg.get("ua_host"):
        try:
            await ua.configure(cfg["ua_host"], dec(cfg["ua_token"]), dec(cfg.get("wg_conf")),
                               cfg.get("cert_sha256"))
        except Exception as e:  # noqa: BLE001
            ua.last_error = str(e)


# ---------------------------------------------------------------- aplikace + auth
app = FastAPI(title="UnifiAdminPro", docs_url=None, redoc_url=None)
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


async def check_scope(who: str, uid: str):
    """Operátor smí pracovat jen s uživateli ve svých rolích."""
    cfg = load_cfg()
    acc = get_account(cfg, who)
    if acc.get("role") == "admin":
        return
    if (await membership()).get(uid) not in allowed_role_ids(cfg, acc):
        raise HTTPException(403, "Tento uživatel nepatří do vašich rolí")


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
@app.get("/api/status")
async def status(who: str = Depends(auth)):
    cfg = load_cfg()
    acc = get_account(cfg, who)
    wg = dec(cfg.get("wg_conf"))
    base = {"user": who, "account_role": acc.get("role"), "site_name": cfg.get("site_name"),
            "roles": [r for r in mapped_roles(cfg) if r["group_id"] in allowed_role_ids(cfg, acc)]}
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
    out = []
    for u in await ua.all_pages("/users", {"expand[]": "access_policy"}):
        u["role_id"] = m.get(u.get("id"))
        if acc.get("role") == "admin" or u["role_id"] in allowed:
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
    if old == r.role_id:
        return {"ok": True}
    await ua.request("POST", f"/user_groups/{r.role_id}/users", json=[uid])
    if old:
        await ua.request("POST", f"/user_groups/{old}/users/delete", json=[uid])
    invalidate_members()
    audit(who, "role", {"user_id": uid, "from": role_name(cfg, old), "to": role_name(cfg, r.role_id)})
    return {"ok": True}


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
    out = []
    for r in mapped_roles(cfg):
        if r["group_id"] not in allowed_role_ids(cfg, acc):
            continue
        try:
            pol = (await ua.request("GET", f"/user_groups/{r['group_id']}/access_policies"))["data"] or []
        except HTTPException:
            pol = []
        out.append({**r, "policies": [x.get("name") for x in pol]})
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


def _acc_public(a: dict) -> dict:
    return {"user": a["user"], "name": a.get("name", ""), "role": a.get("role"),
            "allowed_roles": a.get("allowed_roles", []), "ua_user_id": a.get("ua_user_id")}


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
                                "allowed_roles": allowed, "name": a.name.strip(), "ua_user_id": a.ua_user_id})
        action = "account_create"
    else:
        if user == who and a.role != "admin":
            raise HTTPException(400, "Sami sobě nemůžete odebrat roli správce")
        acc.update(role=a.role, allowed_roles=allowed, name=a.name.strip())
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
    await check_scope(who, uid)
    u = (await ua.request("GET", f"/users/{uid}", params={"expand[]": "access_policy"}))["data"]
    u["role_id"] = (await membership()).get(uid)
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
        await check_scope(who, user_id)
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
    if acc.get("role") != "admin":
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
