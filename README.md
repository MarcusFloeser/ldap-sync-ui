# LDAP Sync UI

Universelles Synchronisationstool zwischen zwei LDAP-Verzeichnissen (z. B. HCL Domino → OpenLDAP) mit Web-Oberfläche. Eine einzelne Python-Datei auf Basis von Flask und ldap3.

## Funktionen

- Mehrere Sync-Jobs anlegen, speichern und löschen (Web-Oberfläche)
- Quelle und Ziel frei konfigurierbar: Host, Port, LDAPS, Bind-DN, Passwort, Base
- Suchfilter als einzige Selektion der Quelle (kein hartcodierter Filter)
- Attribut-Mapping per Textfeld, inkl. Fallbacks und Konstanten
- Abgleich: Einträge anlegen, geänderte Werte aktualisieren, in der Quelle entfernte Attribute im Ziel löschen
- Optional: verwaiste Einträge im Ziel löschen (nur Einträge mit Marker-Attribut)
- Verbindungstest, Dry-Run und Live-Protokoll
- Zeitplan pro Job (alle N Minuten) oder headless per Cron
- Paged Search für grosse Verzeichnisse

## Installation

```bash
pip install -r requirements.txt
export UI_USER=admin UI_PASS=geheim
python ldap_sync_ui.py          # http://127.0.0.1:5000
```

### Docker

```bash
cp .env.example .env            # UI_USER / UI_PASS eintragen
docker compose up -d --build    # http://localhost:5000
```

Die Job-Definitionen liegen im Volume `ldap-sync-data` (`/data/jobs.json`).

## Konfiguration

Umgebungsvariablen:

| Variable    | Default      | Bedeutung                                           |
|-------------|--------------|-----------------------------------------------------|
| `UI_HOST`   | `127.0.0.1`  | Bind-Adresse der Oberfläche                         |
| `UI_PORT`   | `5000`       | Port                                                |
| `UI_USER`   | –            | Benutzername (Basic-Auth, dringend empfohlen)       |
| `UI_PASS`   | –            | Passwort (Basic-Auth, dringend empfohlen)           |
| `SYNC_DATA` | `jobs.json`  | Pfad zur Datei mit den Job-Definitionen             |

Eine Beispielkonfiguration für Domino → OpenLDAP liegt in `jobs.example.json`. Kopiere sie nach `jobs.json` und passe sie an, oder lege den Job direkt in der Oberfläche an.

## Mapping-Syntax

Eine Zeile pro Zielattribut:

| Zeile                    | Bedeutung                                           |
|--------------------------|-----------------------------------------------------|
| `cn=cn`                  | Attribut kopieren                                   |
| `uid=uid\|mail:local`    | `uid` verwenden, sonst Teil der Mailadresse vor `@` |
| `o='Firma'`              | Konstante                                           |
| `# Kommentar`            | Zeile wird ignoriert                                |

Das Schlüsselattribut (z. B. `uid`) muss im Mapping vorkommen. Es wird im Ziel zum RDN: `uid=<wert>,<Ziel-Base>`.

## Headless / Cron

```bash
python ldap_sync_ui.py --run <job-id> --dry-run
python ldap_sync_ui.py --run <job-id>
```

Die Job-ID steht in `jobs.json`. Der Exit-Code ist `0` bei Erfolg, sonst `1`.

```cron
*/30 * * * * cd /opt/ldap-sync-ui && SYNC_DATA=/opt/ldap-sync-ui/jobs.json python ldap_sync_ui.py --run domino-kapo
```

## Verhalten beim Abgleich

- Einträge werden im Ziel über das Schlüsselattribut gesucht (Subtree unter der Ziel-Base).
- Es werden nur die im Mapping genannten Attribute verwaltet. Andere Attribute im Ziel (z. B. `userPassword`) bleiben unberührt.
- Mit der Option «Attribute entfernen» werden verwaltete Attribute gelöscht, die in der Quelle nicht mehr vorhanden sind.
- Mit «Verwaiste Eintraege loeschen» werden Einträge unter der Ziel-Base gelöscht, die das Marker-Attribut tragen, in der Quelle aber nicht mehr vorkommen. Das wird übersprungen, wenn Fehler auftraten oder die Quelle leer war.
- Das Schlüsselattribut wird bei bestehenden Einträgen nie geändert. Ändert sich der Wert in der Quelle, entsteht ein neuer Eintrag.

## Sicherheit

- Passwörter stehen im Klartext in `jobs.json` (Dateirechte 0600). Die Datei ist in `.gitignore` und darf nie committet werden.
- Die Oberfläche lauscht standardmässig nur auf `127.0.0.1`. Bei Zugriff über das Netz: `UI_USER` und `UI_PASS` setzen und einen Reverse-Proxy mit HTTPS davorstellen. Basic-Auth ist sonst unverschlüsselt.
- Aktiviere die TLS-Prüfung (`LDAPS` + Zertifikat prüfen) und hinterlege bei privaten CAs die CA im System-Truststore.
- Verwende für Quelle ein Konto mit Leserechten, für das Ziel ein Konto nur mit Schreibrechten unter der Ziel-Base.

## Grenzen

- Gruppen und Mitgliedschaften werden nicht synchronisiert.
- DNs werden nicht umgeschrieben.
- Passwort-Hashes lassen sich nicht übertragen (Domino gibt sie über LDAP nicht heraus).
- Läufe und Protokolle liegen nur im Speicher und sind nach einem Neustart weg.
- Die Oberfläche läuft auf dem eingebauten Flask-Server, gedacht für den Einsatz im internen Netz.

## Domino → OpenLDAP (Beispiel)

- Quelle: Base `O=Extern`, Filter `(&(objectClass=dominoPerson)(mail=*@example.org))`
- Ziel: Base `ou=Kapo,dc=zh,dc=ch` (muss existieren), Schlüsselattribut `uid`
- Domino-spezifische Attribute (z. B. `dominoUNID`) nicht ins Mapping aufnehmen, sie sind im OpenLDAP-Schema nicht vorhanden.
