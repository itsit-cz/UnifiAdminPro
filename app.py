"""
UniFi Access – jednoduchá správa uživatelů
Backend: FastAPI proxy nad UniFi Access Developer API (port 12445).
API token zůstává na serveru, prohlížeč ho nikdy nevidí.
"""
import json
import os
import secrets
import time
from datetime import datetime
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

UA_HOST = os.environ.get("UA_HOST", "https://192.168.1.1:12445").rstrip("/")
UA_TOKEN = os.environ.get("UA_TOKEN", "")
UA_VERIFY_TLS = os.environ.get("UA_VERIFY_TLS", "false").lower() == "true"
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
AUDIT_FILE = Path(os.environ.get("AUDIT_FILE", "data/audit.jsonl"))

BASE = Path(__file__).parent
app = FastAPI(title="UniFi Access Admin")
security = HTTPBasic()


# ---------------------------------------------------------------- auth + audit
def auth(creds: HTTPBasicCredentials = Depends(security)) -> str:
    ok_user = secrets.compare_digest(creds.username, ADMIN_USER)
    ok_pass = bool(ADMIN_PASSWORD) and secrets.compare_digest(creds.password, ADMIN_PASSWORD)
    if not (ok_user and ok_pass):
        raise HTTPException(401, "Neplatné přihlášení", headers={"WWW-Authenticate": "Basic"})
    return creds.username


def audit(who: str, action: str, detail: dict):
    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    rec = {"ts": datetime.now().isoformat(timespec="seconds"), "who": who, "action": action, **detail}
    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------- UA klient
client = httpx.AsyncClient(
    base_url=f"{UA_HOST}/api/v1/developer",
    headers={"Authorization": f"Bearer {UA_TOKEN}", "Accept": "application/json"},
    verify=UA_VERIFY_TLS,
    timeout=20,
)


async def ua(method: str, path: str, **kw):
    try:
        r = await client.request(method, path, **kw)
    except httpx.HTTPError as e:
        raise HTTPException(502, f"UniFi Access nedostupné: {e}")
    try:
        body = r.json()
    except ValueError:
        raise HTTPException(502, f"Neočekávaná odpověď ({r.status_code}): {r.text[:200]}")
    if r.status_code >= 400 or body.get("code") != "SUCCESS":
        raise HTTPException(r.status_code if r.status_code >= 400 else 400,
                            f"{body.get('code')}: {body.get('msg')}")
    return body


async def ua_all_pages(path: str, params: dict | None = None):
    params = dict(params or {})
    out, page = [], 1
    while True:
        params.update(page_num=page, page_size=100)
        body = await ua("GET", path, params=params)
        data = body.get("data") or []
        out.extend(data)
        pag = body.get("pagination") or {}
        if not data or len(out) >= pag.get("total", len(out)):
            return out
        page += 1


# ---------------------------------------------------------------- modely
class NewUser(BaseModel):
    first_name: str
    last_name: str
    user_email: str | None = None
    employee_number: str | None = None
    access_policy_ids: list[str] = []
    pin_code: str | None = None


class StatusIn(BaseModel):
    status: str  # ACTIVE | DEACTIVATED


class PoliciesIn(BaseModel):
    access_policy_ids: list[str]


class PinIn(BaseModel):
    pin_code: str


# ---------------------------------------------------------------- API
@app.get("/api/users")
async def users(_: str = Depends(auth)):
    return await ua_all_pages("/users", {"expand[]": "access_policy"})


@app.get("/api/policies")
async def policies(_: str = Depends(auth)):
    return (await ua("GET", "/access_policies"))["data"]


@app.get("/api/doors")
async def doors(_: str = Depends(auth)):
    return (await ua("GET", "/doors"))["data"]


@app.post("/api/users")
async def create_user(u: NewUser, who: str = Depends(auth)):
    body = {k: v for k, v in u.model_dump(include={"first_name", "last_name", "user_email",
                                                    "employee_number"}).items() if v}
    body["onboard_time"] = int(time.time())
    created = (await ua("POST", "/users", json=body))["data"]
    uid = created["id"]
    if u.access_policy_ids:
        await ua("PUT", f"/users/{uid}/access_policies",
                 json={"access_policy_ids": u.access_policy_ids})
    if u.pin_code:
        await ua("PUT", f"/users/{uid}/pin_codes", json={"pin_code": u.pin_code})
    audit(who, "create", {"user_id": uid, "name": f"{u.first_name} {u.last_name}",
                          "policies": u.access_policy_ids, "pin": bool(u.pin_code)})
    return created


@app.put("/api/users/{uid}/status")
async def set_status(uid: str, s: StatusIn, who: str = Depends(auth)):
    if s.status not in ("ACTIVE", "DEACTIVATED"):
        raise HTTPException(400, "Status musí být ACTIVE nebo DEACTIVATED")
    await ua("PUT", f"/users/{uid}", json={"status": s.status})
    audit(who, "status", {"user_id": uid, "status": s.status})
    return {"ok": True}


@app.put("/api/users/{uid}/policies")
async def set_policies(uid: str, p: PoliciesIn, who: str = Depends(auth)):
    await ua("PUT", f"/users/{uid}/access_policies", json={"access_policy_ids": p.access_policy_ids})
    audit(who, "policies", {"user_id": uid, "policies": p.access_policy_ids})
    return {"ok": True}


@app.put("/api/users/{uid}/pin")
async def set_pin(uid: str, p: PinIn, who: str = Depends(auth)):
    if not p.pin_code.isdigit() or not 4 <= len(p.pin_code) <= 8:
        raise HTTPException(400, "PIN musí mít 4–8 číslic")
    await ua("PUT", f"/users/{uid}/pin_codes", json={"pin_code": p.pin_code})
    audit(who, "pin", {"user_id": uid})
    return {"ok": True}


@app.delete("/api/users/{uid}")
async def delete_user(uid: str, who: str = Depends(auth)):
    # UA dovolí smazat jen deaktivovaného uživatele (UA 3.1.30+)
    await ua("PUT", f"/users/{uid}", json={"status": "DEACTIVATED"})
    await ua("DELETE", f"/users/{uid}")
    audit(who, "delete", {"user_id": uid})
    return {"ok": True}


@app.get("/api/logs")
async def logs(hours: int = 24, user_id: str | None = None, page_size: int = 200,
               _: str = Depends(auth)):
    now = int(time.time())
    body = {"topic": "door_openings", "since": now - hours * 3600, "until": now}
    if user_id:
        body["actor_id"] = user_id
    data = (await ua("POST", "/system/logs", params={"page_num": 1, "page_size": page_size},
                     json=body))["data"] or {}
    out = []
    for h in data.get("hits", []):
        s = h.get("_source", h)
        ev, actor = s.get("event", {}), s.get("actor", {})
        door = next((t.get("display_name") for t in s.get("target", [])
                     if t.get("type") == "door"), None)
        out.append({
            "time": h.get("@timestamp") or ev.get("published"),
            "user": actor.get("display_name"),
            "user_id": actor.get("id"),
            "door": door,
            "result": ev.get("result"),
            "method": (s.get("authentication") or {}).get("credential_provider"),
            "message": ev.get("display_message"),
        })
    return out


@app.get("/api/audit")
async def audit_log(limit: int = 200, _: str = Depends(auth)):
    if not AUDIT_FILE.exists():
        return []
    lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()[-limit:]
    return [json.loads(l) for l in reversed(lines)]


# ---------------------------------------------------------------- frontend
@app.get("/")
async def index(_: str = Depends(auth)):
    return FileResponse(BASE / "static" / "index.html")


app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
