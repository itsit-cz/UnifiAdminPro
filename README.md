# UnifiAdminPro
Správa uživatelů v UNIFI Access a Unifi Protect

Webové rozhraní pro přidávání/odebírání uživatelů UniFi Access a kontrolu průchodů.
Backend (FastAPI) volá oficiální UniFi Access Developer API; API token zůstává na serveru.

## Funkce
- **Uživatelé** – seznam, hledání, filtr dle stavu a politiky, přehled (aktivní / deaktivovaní / aktivní bez politiky)
- přidání uživatele (jméno, e-mail, os. číslo, PIN, přístupové politiky)
- změna politik, nastavení PINu, deaktivace/aktivace, trvalé smazání (nejdřív deaktivuje, pak smaže)
- **Průchody** – log otevření dveří za 1 h / 24 h / 7 / 30 dní, filtr podle uživatele
- **Audit změn** – kdo a kdy co změnil přes toto rozhraní (`data/audit.jsonl`)

## Nasazení
1. V UniFi Access: *Settings → General → Advanced → API Token → Create New*
   (oprávnění: view/edit user, view policy, view system log, view door).
2. `cp .env.example .env` a vyplnit `UA_HOST`, `UA_TOKEN`, `ADMIN_PASSWORD`.
3. `docker compose up -d --build` → http://server:8080

### Portainer
*Stacks → Add stack → Repository*: URL `https://github.com/itsit-cz/UnifiAdminPro`, reference `refs/heads/main`,
compose path `docker-compose.yml`. V *Environment variables* doplnit `UA_HOST`, `UA_TOKEN`, `ADMIN_PASSWORD`
(volitelně `HOST_PORT`, `ADMIN_USER`, `UA_VERIFY_TLS`) a *Deploy the stack*.

Bez Dockeru: `pip install -r requirements.txt` a `uvicorn app:app --host 0.0.0.0 --port 8080`
(proměnné z `.env` exportovat do prostředí).

## Poznámky
- Mazání uživatelů přes API vyžaduje UniFi Access 3.1.30+.
- Přihlášení je HTTP Basic – provozujte jen ve vnitřní síti, příp. za reverse proxy s HTTPS.
- NFC karty se zatím jen zobrazují (počet); párování karty přes čtečku lze doplnit
  (API `/credentials/nfc_cards/sessions`).

## Plán (v2)
- jedna instance = jedna škola (samostatný Docker stack, šablona pro DockerStackMover/Portainer)
- WireGuard klient v userspace (wireproxy) přímo v image – konfigurace z UDM se nahraje v aplikaci
- průvodce prvním spuštěním (WG konfigurace, adresa konzole, API token, test připojení)
- šifrovaná tajemství, pinning certifikátu konzole místo `verify=false`
- 2FA, Traefik labely
