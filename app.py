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
    return json.loads(CONFIG.read_text()) if CONFIG.exists() else None


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

    async def request(self, method: str, path: str, **kw):
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
        if r.status_code >= 400 or body.get("code") != "SUCCESS":
            self.last_error = f"{body.get('code')}: {body.get('msg')}"
            raise HTTPException(r.status_code if r.status_code >= 400 else 400, self.last_error)
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
    if not load_cfg():
        raise HTTPException(409, "Aplikace ještě není nainstalována")
    user = request.session.get("user")
    if not user:
        raise HTTPException(401, "Nepřihlášen")
    return user


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
        if body.get("code") != "SUCCESS":
            hint = (" – token nemá potřebná oprávnění. Vytvořte nový v Access → Settings → General → API Token "
                    "s oprávněními view/edit pro User, Access Policy, Door/Location a System Log."
                    if body.get("code") == "CODE_UNAUTHORIZED" else "")
            steps.append({"ok": False, "text": f"API token odmítnut: {body.get('code')} – {body.get('msg')}{hint}"})
            return {"ok": False, "steps": steps}
        steps.append({"ok": True, "text": "API token je platný (čtení uživatelů)"})
        return {"ok": True, "steps": steps, "cert_sha256": fp,
                "users_total": (body.get("pagination") or {}).get("total")}
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
    save_cfg({"site_name": s.site_name.strip(), "admin": {"user": s.admin_user.strip(),
              "pw": hash_pw(s.admin_password)}, "ua_host": host, "ua_token": enc(token),
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
    cfg = load_cfg() or {}
    adm = cfg.get("admin", {})
    if li.user != adm.get("user") or not check_pw(li.password, adm.get("pw", "x$00$00")):
        FAILS.setdefault(ip, []).append(time.time())
        raise HTTPException(401, "Neplatné jméno nebo heslo")
    request.session["user"] = li.user
    return {"ok": True}


@app.post("/api/logout")
async def logout(request: Request):
    request.session.clear()
    return {"ok": True}


# ---------------------------------------------------------------- nastavení
@app.get("/api/status")
async def status(who: str = Depends(auth)):
    cfg = load_cfg()
    wg = dec(cfg.get("wg_conf"))
    return {"user": who, "site_name": cfg.get("site_name"), "ua_host": cfg.get("ua_host"),
            "wireguard": bool(wg), "wg_endpoint": wg_endpoint(wg), "tunnel_up": ua.tunnel.running,
            **(ua.tunnel.stats() if wg else {}),
            "cert_sha256": cfg.get("cert_sha256"), "last_error": ua.last_error}


class SaveConnIn(ConnIn):
    cert_sha256: str


@app.post("/api/settings/test")
async def settings_test(c: ConnIn, who: str = Depends(auth)):
    return await test_conn(*resolve_conn(c, load_cfg()))


@app.post("/api/settings/connection")
async def settings_save(c: SaveConnIn, who: str = Depends(auth)):
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
    if not check_pw(p.old, cfg["admin"]["pw"]):
        raise HTTPException(400, "Původní heslo nesouhlasí")
    if len(p.new) < 10:
        raise HTTPException(400, "Heslo musí mít alespoň 10 znaků")
    cfg["admin"]["pw"] = hash_pw(p.new)
    save_cfg(cfg)
    audit(who, "password", {})
    return {"ok": True}


# ---------------------------------------------------------------- UniFi Access API
class NewUser(BaseModel):
    first_name: str
    last_name: str
    user_email: str | None = None
    employee_number: str | None = None
    access_policy_ids: list[str] = []
    pin_code: str | None = None


class StatusIn(BaseModel):
    status: str


class PoliciesIn(BaseModel):
    access_policy_ids: list[str]


class PinIn(BaseModel):
    pin_code: str


@app.get("/api/users")
async def users(_: str = Depends(auth)):
    return await ua.all_pages("/users", {"expand[]": "access_policy"})


@app.get("/api/policies")
async def policies(_: str = Depends(auth)):
    return (await ua.request("GET", "/access_policies"))["data"]


@app.post("/api/users")
async def create_user(u: NewUser, who: str = Depends(auth)):
    if u.pin_code and (not u.pin_code.isdigit() or not 4 <= len(u.pin_code) <= 8):
        raise HTTPException(400, "PIN musí mít 4–8 číslic")
    body = {k: v for k, v in u.model_dump(include={"first_name", "last_name", "user_email",
                                                    "employee_number"}).items() if v}
    body["onboard_time"] = int(time.time())
    created = (await ua.request("POST", "/users", json=body))["data"]
    uid = created["id"]
    if u.access_policy_ids:
        await ua.request("PUT", f"/users/{uid}/access_policies",
                         json={"access_policy_ids": u.access_policy_ids})
    if u.pin_code:
        await ua.request("PUT", f"/users/{uid}/pin_codes", json={"pin_code": u.pin_code})
    audit(who, "create", {"user_id": uid, "name": f"{u.first_name} {u.last_name}",
                          "policies": u.access_policy_ids, "pin": bool(u.pin_code)})
    return created


@app.put("/api/users/{uid}/status")
async def set_status(uid: str, s: StatusIn, who: str = Depends(auth)):
    if s.status not in ("ACTIVE", "DEACTIVATED"):
        raise HTTPException(400, "Status musí být ACTIVE nebo DEACTIVATED")
    await ua.request("PUT", f"/users/{uid}", json={"status": s.status})
    audit(who, "status", {"user_id": uid, "status": s.status})
    return {"ok": True}


@app.put("/api/users/{uid}/policies")
async def set_policies(uid: str, p: PoliciesIn, who: str = Depends(auth)):
    await ua.request("PUT", f"/users/{uid}/access_policies",
                     json={"access_policy_ids": p.access_policy_ids})
    audit(who, "policies", {"user_id": uid, "policies": p.access_policy_ids})
    return {"ok": True}


@app.put("/api/users/{uid}/pin")
async def set_pin(uid: str, p: PinIn, who: str = Depends(auth)):
    if not p.pin_code.isdigit() or not 4 <= len(p.pin_code) <= 8:
        raise HTTPException(400, "PIN musí mít 4–8 číslic")
    await ua.request("PUT", f"/users/{uid}/pin_codes", json={"pin_code": p.pin_code})
    audit(who, "pin", {"user_id": uid})
    return {"ok": True}


@app.delete("/api/users/{uid}")
async def delete_user(uid: str, who: str = Depends(auth)):
    await ua.request("PUT", f"/users/{uid}", json={"status": "DEACTIVATED"})
    await ua.request("DELETE", f"/users/{uid}")
    audit(who, "delete", {"user_id": uid})
    return {"ok": True}


@app.get("/api/logs")
async def logs(hours: int = 24, user_id: str | None = None, _: str = Depends(auth)):
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
    return out


@app.get("/api/audit")
async def audit_log(limit: int = 200, _: str = Depends(auth)):
    if not AUDIT_FILE.exists():
        return []
    lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()[-limit:]
    return [json.loads(line) for line in reversed(lines)]


app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
