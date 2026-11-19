# SyncPro
Správa uživatelů v UNIFI Access a Unifi Protect

Jednoduché webové rozhraní pro UniFi Access. Každá lokalita (škola) má **vlastní instanci** v Dockeru,
ke konzoli se připojuje přímo nebo přes **WireGuard VPN z UDM**, který běží uvnitř kontejneru.

## Funkce
- **Uživatelé** – seznam, hledání (i podle SPZ a karty), filtry, přidání, deaktivace/aktivace, trvalé smazání
- **Role** – skupiny uživatelů z UniFi Access namapované jako role; přístup ke dveřím se řídí politikami skupiny,
  každý uživatel má právě jednu roli
- **Účty aplikace** – *správce* (vše) a *operátor* (zakládá a spravuje jen uživatele v povolených rolích,
  nemůže mazat, měnit nastavení ani číst audit). Volba *Vidí všechny uživatele*: operátor vidí i uživatele bez role
  a v cizích rolích; uživatele bez role může zařadit do svých rolí, ostatní jen prohlíží
- **Detail uživatele** – úprava údajů, změna role, PIN (nastavit/odebrat),
  **NFC karty** (načtení přiložením ke čtečce, ruční token, přeřazení, odebrání), **SPZ** (přidat/odebrat, UA 3.3.10+)
- **Průchody** – log otevření dveří (1 h – 30 dní), filtr dle uživatele
- **Audit změn** – kdo a kdy co změnil přes rozhraní
- **Nastavení** – změna připojení (adresa, token, WireGuard), test připojení, změna hesla
- **Aktualizace z webu** – zobrazí nainstalovanou a nejnovější verzi, tlačítkem spustí redeploy stacku v Portaineru
- **Průvodce instalací** – při nasazení se nic nenastavuje, vše se vyplní v prohlížeči

## Nasazení v Portaineru
1. *Stacks → Add stack → Repository*
   - Repository URL: `https://github.com/itsit-cz/UnifiAdminPro`
   - Reference: `refs/heads/main`, Compose path: `docker-compose.yml`
   - Environment variables: **žádné**
2. *Deploy the stack* – Portainer stáhne hotový image `ghcr.io/itsit-cz/unifiadminpro:latest`
   (sestavuje ho GitHub Actions po každém commitu do `main`, amd64 i arm64).
3. *Containers → unifiadminpro → Logs* – zkopírujte **instalační kód**.
4. Otevřete `http://server:8080` a projděte průvodce:
   instalační kód → název lokality a správce → adresa konzole, API token, WireGuard → *Otestovat* → *Dokončit*.

Více škol na jednom hostu = více stacků; v každém změňte levou stranu portu (`8081:8080`, …).

## Příprava na straně školy (UDM)
1. **API token:** UniFi Access → Settings → General → API Token → Create New – zaškrtněte **všechna oprávnění**
   (minimálně view/edit pro User, Access Policy, Credential, Device, Location a System Log).
2. **WireGuard klient:** UniFi Network → Settings → VPN → VPN Server → WireGuard → přidat klienta
   (např. „SyncPro – DC“) → stáhnout `.conf` a nahrát ho v průvodci.
   UDM musí být dostupné z internetu na portu WireGuard (veřejná IP, ne CGNAT).
3. **Adresa konzole:** LAN IP konzole UniFi Access (u UDM jeho IP, např. `172.16.0.1`), port 12445.

## Role a účty
1. V UniFi Access vytvořte skupiny uživatelů (např. Žáci, Učitelé) a přiřaďte jim přístupové politiky.
2. Nastavení → **Role**: zaškrtněte skupiny, které se mají používat jako role, případně je přejmenujte.
3. Účet v aplikaci přidělíte přímo uživateli: **Upravit → Účet v aplikaci** → typ (operátor/správce), povolené role
   a heslo (lze vygenerovat). Přihlašovací jméno se předvyplní z e-mailu. Přehled všech účtů je v Nastavení → Účty aplikace.

Členství v roli se čte ze skupin v UniFi Access – změny provedené přímo v Access se v aplikaci projeví.

## Aktualizace z webu
Nastavení → Aktualizace → způsob:
- **Portainer API** – adresa Portaineru, přístupový token (*My account → Access tokens*) a ID stacku (číslo v URL stacku).
  Aplikace zavolá redeploy stacku se stažením nového image. Doporučeno: samostatný uživatel Portaineru s přístupem jen k danému prostředí.
- **Webhook stacku** – URL z *Stacks → stack → Editor → Webhooks* (v Portainer CE nemusí být k dispozici).

Nejnovější verze = poslední úspěšný build image na GitHubu. Průběh je v logu kontejneru (řádky `[update]`).

## Bezpečnost
- Instalaci lze dokončit jen s jednorázovým kódem z logu kontejneru.
- API token a WireGuard konfigurace jsou v `data` šifrované klíčem z volume `keys` – zálohujte volumy odděleně.
- Certifikát konzole je self-signed, proto se při instalaci uloží jeho **otisk (SHA-256)** a ověřuje se při
  každém spojení. Při výměně certifikátu ho potvrďte v Nastavení → Otestovat → Uložit.
- Přihlášení: hesla scrypt, session cookie (8 h), 5 chybných pokusů = blokace na 5 minut.
- WireGuard běží v userspace ([wireproxy](https://github.com/whyvl/wireproxy)) – kontejner nepotřebuje
  `NET_ADMIN` a každá instance má vlastní izolovaný tunel (školy mohou mít stejné rozsahy).
- Do internetu vystavujte jen přes reverse proxy s HTTPS (Traefik) – ideálně s omezením IP.

## Vývoj
```
pip install -r requirements.txt
DATA_DIR=./data KEYS_DIR=./keys uvicorn app:app --reload --port 8080
```
(Pro WireGuard je potřeba binárka `wireproxy` v PATH nebo `WIREPROXY_BIN`.)
Lokální sestavení image: `docker build -t ghcr.io/itsit-cz/unifiadminpro:latest .`

## Plán
- 2FA (TOTP), více správců
- párování NFC karet přes čtečku
- UniFi Protect – záběr z kamery k průchodu
