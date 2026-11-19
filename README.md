# UnifiAdminPro
Správa uživatelů v UNIFI Access a Unifi Protect

Jednoduché webové rozhraní pro UniFi Access. Každá lokalita (škola) má **vlastní instanci** v Dockeru,
ke konzoli se připojuje přímo nebo přes **WireGuard VPN z UDM**, který běží uvnitř kontejneru.

## Funkce
- **Uživatelé** – seznam, hledání, filtry, přidání (jméno, e-mail, os. číslo, PIN, politiky), změna politik,
  PIN, deaktivace/aktivace, trvalé smazání
- **Průchody** – log otevření dveří (1 h – 30 dní), filtr dle uživatele
- **Audit změn** – kdo a kdy co změnil přes rozhraní
- **Nastavení** – změna připojení (adresa, token, WireGuard), test připojení, změna hesla
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
1. **API token:** UniFi Access → Settings → General → Advanced → API Token → Create New
   (oprávnění: uživatelé, politiky, dveře, systémový log).
2. **WireGuard klient:** UniFi Network → Settings → VPN → VPN Server → WireGuard → přidat klienta
   (např. „UnifiAdminPro – DC“) → stáhnout `.conf` a nahrát ho v průvodci.
   UDM musí být dostupné z internetu na portu WireGuard (veřejná IP, ne CGNAT).
3. **Adresa konzole:** LAN IP konzole UniFi Access (u UDM jeho IP, např. `172.16.0.1`), port 12445.

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
