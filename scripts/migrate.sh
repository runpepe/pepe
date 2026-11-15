#!/bin/sh
set -eu
: "${DATABASE_URL:?Set DATABASE_URL in Doppler}"
SCHEMAHERO=${SCHEMAHERO:-schemahero}
ddl=$(mktemp -d "${TMPDIR:-/tmp}/pepe-ddl.XXXXXX")
trap 'rm -rf "$ddl"' EXIT HUP INT TERM
"$SCHEMAHERO" plan --driver postgres --uri "$DATABASE_URL" --spec-file schema/tables/ --out "$ddl"
"$SCHEMAHERO" apply --driver postgres --uri "$DATABASE_URL" --ddl "$ddl"
printf '%s\n' 'Migrations applied successfully.'
