#!/bin/sh
# Besitzer von /data beim Start korrigieren (Volumes koennen root gehoeren),
# danach als unprivilegierter Benutzer starten.
set -e
chown ldapsync:ldapsync /data
exec setpriv --reuid=ldapsync --regid=ldapsync --clear-groups "$@"
