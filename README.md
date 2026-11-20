# 🎁 Wichteln – Familien-Wichtel-App

Web-App fürs Familien-Wichteln. Man legt Familien an, sammelt Wünsche und lost per Zufall aus. Jeder sieht nur, wen er selbst beschenkt. Läuft gratis auf Cloudflare (Workers + D1-Datenbank).

## Funktionen
- Wichtelprojekt pro Familie und Jahr: Budget (CHF), Spielregeln, Anmeldeschluss
- Anmeldung mit Name, 4-stelliger PIN und Wünschen (Text + Link). Kein Konto nötig.
- Eltern können Kinder ohne Handy eintragen. Die beiden ziehen sich gegenseitig nicht.
- Der Admin schliesst die Anmeldung, legt die Anzahl Geschenke fest und lost aus. Paarungen vom Vorjahr werden möglichst vermieden.
- Wünsche reservieren: Andere Wichtel sehen „reserviert“, aber nicht von wem. Der Beschenkte sieht nichts.
- Auflösung nach Weihnachten, Archiv, neues Jahr mit einem Klick

## Einrichten (einmalig, ca. 15 Minuten)

1. **Cloudflare-Konto anlegen:** auf https://dash.cloudflare.com/sign-up (gratis, keine Kreditkarte nötig).
2. Im Cloudflare-Dashboard links **Compute (Workers)** → **Workers & Pages** öffnen und **Create application** klicken.
3. **Import a repository** wählen, dann dein GitHub-Konto verbinden und dieses Repository (`wichteln`) auswählen.
4. Die Einstellungen so lassen, wie sie sind (Deploy-Befehl: `npx wrangler deploy`), und **Deploy** klicken.
   - Die Datenbank wird dabei automatisch angelegt. Die Tabellen erstellt die App beim ersten Aufruf selbst.
5. Nach etwa einer Minute ist die App online unter `https://wichteln.<dein-name>.workers.dev`.
6. Diesen Link der Familie schicken. Fertig.

Jede Änderung, die du später hier auf GitHub machst, geht automatisch online.

## So läuft das Wichteln
1. **Neues Wichtelprojekt** anlegen und dabei eine Admin-PIN wählen.
2. Den Projekt-Link teilen (steht im Admin-Bereich). Alle tragen sich mit „Ich mache mit“ ein.
3. Admin: **Anmeldung schliessen**, Anzahl Geschenke wählen, **Jetzt auslosen**.
4. Alle sehen unter **Mein Wichteln**, wen sie beschenken, und können Wünsche reservieren.
5. Nach Weihnachten: **Auflösung veröffentlichen**, dann **Im Archiv speichern**.
6. Nächstes Jahr: **Neues Wichteljahr starten** (Einstellungen und Admin-PIN werden übernommen).

## Datenschutz
- Die Einteilung wird im Browser verschlüsselt, mit einem Schlüssel pro Person, den nur deren PIN öffnet. Auf dem Server liegt sie nur verschlüsselt. Auch der Admin sieht sie in der App nicht.
- Der Server prüft PINs und sperrt eine Person nach 5 falschen Versuchen für 10 Minuten.
- Grenze: Eine 4-stellige PIN ist kein Hochsicherheitsschutz. Wer Zugriff auf das Cloudflare-Konto hat, könnte die Datenbank mit viel Aufwand knacken. Für ein Familien-Wichteln reicht das.
- Vergessene PINs lassen sich nicht wiederherstellen. Lösung: Admin → Auslosung zurücksetzen, Person entfernen, neu anmelden lassen, neu auslosen.

## Kosten
Der Cloudflare-Gratisplan reicht für eine Familie bei Weitem (Tageslimits im Millionenbereich).

## Aufbau
```
public/index.html   Oberfläche (Design)
public/app.js       App-Logik im Browser
public/draw.js      Auslosung (Zufall mit Regeln)
src/worker.js       Server (API, PIN-Prüfung, Datenbank)
wrangler.toml       Cloudflare-Konfiguration
test/               Lokaler Test (node test/server.mjs, dann node test/e2e.cjs)
```
