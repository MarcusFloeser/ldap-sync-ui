# LDAP Sync UI

Universelles Synchronisationstool zwischen zwei LDAP-Verzeichnissen (z. B. HCL Domino → OpenLDAP) mit Web-Oberfläche, Anmeldung und Zeitplan.

## Funktionen

- Anmeldeseite mit Sitzungen, Benutzerverwaltung und Passwort ändern
- Mehrere Sync-Jobs anlegen, speichern und löschen
- Quelle und Ziel nebeneinander konfigurierbar: Host, Port, LDAPS, Bind-DN, Passwort, Base
- Suchfilter als einzige Selektion der Quelle (kein hartcodierter Filter)
- Attribut-Mapping per Textfeld, inkl. Fallbacks und Konstanten
- Abgleich: Einträge anlegen, geänderte Werte aktualisieren, in der Quelle entfernte Attribute im Ziel löschen
- Optional: verwaiste Einträge im Ziel löschen (nur Einträge mit Marker-Attribut)
- Verbindungstest, Dry-Run, Live-Protokoll und Statistik
- **Zeitplan pro Job als Cron-Ausdruck** (läuft im Container mit, kein Host-Cron nötig)
- Paged Search für grosse Verzeichnisse

## Schnellstart mit Docker Compose

```bash
cp .env.example .env            # optional anpassen
docker compose up -d --build    # http://localhost:5000
```

Beim ersten Aufruf der Seite öffnet sich die **Einrichtung**: Lege dort den ersten Benutzer an. Alternativ setzt du `UI_USER` und `UI_PASS` (Passwort mindestens 8 Zeichen) in der `.env`. Dann wird dieser Benutzer beim ersten Start automatisch angelegt.

Rufe die Seite nach dem Start möglichst sofort selbst auf oder setze `UI_USER`/`UI_PASS`. Solange kein Benutzer existiert, kann jeder, der die Seite erreicht, den ersten Benutzer anlegen.

Alle Daten liegen im Volume `ldap-sync-data` (`/data`): `jobs.json`, `users.json` und `.secret_key`.

### Ohne Docker

```bash
pip install -r requirements.txt
python ldap_sync_ui.py          # http://127.0.0.1:5000
```

## Zeitplan (Cron)

Jeder Job hat in der Oberfläche das Feld **Zeitplan (Cron-Ausdruck)**. Der Zeitplaner läuft im selben Container wie die Oberfläche. Ein zweiter Container oder ein Cron auf dem Host ist nicht nötig. Er prüft alle 15 Sekunden, ob ein Job fällig ist, und startet ihn wie «Sync starten». Dabei gilt:

| Ausdruck        | Bedeutung                              |
|-----------------|----------------------------------------|
| `*/30 * * * *`  | alle 30 Minuten                        |
| `15 2 * * *`    | täglich um 02:15 Uhr                   |
| `0 6 * * 1-5`   | Montag bis Freitag um 06:00 Uhr        |

- Format: `Minute Stunde Tag Monat Wochentag`.
- Die Zeiten gelten in der Zeitzone des Containers. Sie wird in `docker-compose.yml` über `TZ` gesetzt (Standard `Europe/Zurich`).
- Das Feld «oder: alle N Minuten» gilt nur, wenn kein Cron-Ausdruck gesetzt ist.
- Die Oberfläche zeigt den nächsten geplanten Lauf und den Status des letzten Laufs an.
- Läuft ein Job beim Fälligwerden noch, wird dieser Termin übersprungen. Verpasste Termine (z. B. während der Container stand) werden nicht nachgeholt.
- Unvollständige oder ungültige Jobs werden vom Zeitplaner nicht gestartet.

Wer lieber einen externen Cron nutzt, kann einen Job weiterhin einzeln ausführen:

```bash
docker compose exec -u ldapsync ldap-sync python ldap_sync_ui.py --run <job-id>
```

## Benutzer

- In der Oberfläche unter **Benutzer** lassen sich Benutzer hinzufügen und löschen. **Passwort ändern** ändert das eigene Passwort. Alle Benutzer haben dieselben Rechte.
- Auf der Kommandozeile (legt an oder setzt das Passwort zurück, z. B. bei vergessenem Passwort):

```bash
docker compose exec -u ldapsync ldap-sync python ldap_sync_ui.py --add-user admin
```

Verwende `-u ldapsync`, damit die Datei `users.json` dem richtigen Benutzer gehört.

## Konfiguration

Umgebungsvariablen (in Compose über die `.env`):

| Variable        | Default      | Bedeutung                                                     |
|-----------------|--------------|---------------------------------------------------------------|
| `UI_HOST`       | `127.0.0.1`  | Bind-Adresse der Oberfläche (im Container `0.0.0.0`)          |
| `UI_PORT`       | `5000`       | Port                                                          |
| `SYNC_DATA`     | `jobs.json`  | Pfad zur Job-Datei; `users.json` und `.secret_key` daneben    |
| `UI_USER`/`UI_PASS` | –        | legt beim Start den ersten Benutzer an, falls noch keiner existiert |
| `SECRET_KEY`    | automatisch  | Schlüssel für Session-Cookies (sonst `.secret_key` im Datenordner) |
| `SESSION_HOURS` | `8`          | Gültigkeit der Anmeldung                                      |
| `COOKIE_SECURE` | `0`          | `1` = Cookie nur über HTTPS (nur setzen, wenn HTTPS vorgeschaltet ist) |
| `BEHIND_PROXY`  | `0`          | `1` = `X-Forwarded-*` eines Reverse-Proxys beachten           |
| `TZ`            | `Europe/Zurich` (Compose) | Zeitzone für Cron-Zeitpläne                     |

Eine Beispielkonfiguration für Domino → OpenLDAP liegt in `jobs.example.json`. Du kannst den Job auch direkt in der Oberfläche anlegen.

## Mapping-Syntax

Eine Zeile pro Zielattribut:

| Zeile                    | Bedeutung                                           |
|--------------------------|-----------------------------------------------------|
| `cn=cn`                  | Attribut kopieren                                   |
| `uid=uid\|mail:local`    | `uid` verwenden, sonst Teil der Mailadresse vor `@` |
| `o='Firma'`              | Konstante                                           |
| `# Kommentar`            | Zeile wird ignoriert                                |

Das Schlüsselattribut (z. B. `uid`) muss im Mapping vorkommen. Es wird im Ziel zum RDN: `uid=<wert>,<Ziel-Base>`.

## Verhalten beim Abgleich

- Einträge werden im Ziel über das Schlüsselattribut gesucht (Subtree unter der Ziel-Base).
- Es werden nur die im Mapping genannten Attribute verwaltet. Andere Attribute im Ziel (z. B. `userPassword`) bleiben unberührt.
- Mit der Option «Attribute entfernen» werden verwaltete Attribute gelöscht, die in der Quelle nicht mehr vorhanden sind.
- Mit «Verwaiste Einträge im Ziel löschen» werden Einträge unter der Ziel-Base gelöscht, die das Marker-Attribut tragen, in der Quelle aber nicht mehr vorkommen. Das wird übersprungen, wenn Fehler auftraten oder die Quelle leer war.
- Das Schlüsselattribut wird bei bestehenden Einträgen nie geändert. Ändert sich der Wert in der Quelle, entsteht ein neuer Eintrag.

## Sicherheit

- Die Anmeldung nutzt Session-Cookies (HttpOnly, SameSite=Lax) mit CSRF-Schutz. Passwörter werden mit PBKDF2 gehasht, nach 5 Fehlversuchen von derselben Adresse wird die Anmeldung für 10 Minuten gesperrt.
- Die Seite spricht nur HTTP. Stelle für den Zugriff über das Netz einen Reverse-Proxy mit HTTPS davor und setze dann `COOKIE_SECURE=1` und `BEHIND_PROXY=1`. Mit `COOKIE_SECURE=1` über reines HTTP ist keine Anmeldung möglich.
- Die LDAP-Passwörter der Jobs stehen im Klartext in `jobs.json` (Dateirechte 0600). Die Oberfläche zeigt sie nur maskiert an. Die Datei ist in `.gitignore` und darf nie committet werden.
- Verwende für die Quelle ein Konto mit Leserechten, für das Ziel ein Konto nur mit Schreibrechten unter der Ziel-Base.
- Aktiviere die TLS-Prüfung (LDAPS + «TLS-Zertifikat prüfen») und hinterlege bei privaten CAs die CA im System-Truststore.

## Grenzen

- Gruppen und Mitgliedschaften werden nicht synchronisiert.
- DNs werden nicht umgeschrieben.
- Passwort-Hashes lassen sich nicht übertragen (Domino gibt sie über LDAP nicht heraus).
- Läufe und Protokolle liegen nur im Speicher und sind nach einem Neustart weg.
- Es gibt nur eine Benutzerrolle, alle Benutzer dürfen alles.
- Die Oberfläche läuft auf dem eingebauten Flask-Server und ist für den Einsatz im internen Netz hinter einem Reverse-Proxy gedacht.

## Domino → OpenLDAP (Beispiel)

- Quelle: Base `O=Extern`, Filter `(&(objectClass=dominoPerson)(mail=*@example.org))`
- Ziel: Base `ou=Kapo,dc=zh,dc=ch` (muss existieren), Schlüsselattribut `uid`
- Domino-spezifische Attribute (z. B. `dominoUNID`) nicht ins Mapping aufnehmen, sie sind im OpenLDAP-Schema nicht vorhanden.

## Projektstruktur

```
ldap_sync_ui.py      Backend (Flask, Sync-Logik, Zeitplaner)
templates/           login.html, app.html
static/              style.css, app.js
Dockerfile, entrypoint.sh, docker-compose.yml
jobs.example.json    Beispiel-Job
```
