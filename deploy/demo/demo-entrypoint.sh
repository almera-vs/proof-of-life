#!/bin/sh
set -eu

docker-entrypoint.sh postgres \
  -c wal_level=replica \
  -c archive_mode=on \
  -c "archive_command=pgbackrest archive-push %p" \
  -c archive_timeout=10 &
server=$!

until pg_isready -q -h 127.0.0.1 -U postgres; do
  kill -0 "$server" 2>/dev/null || exit 1
  sleep 1
done

if [ ! -f /var/lib/postgresql/data/demo-seeded ]; then
  su postgres -c "psql -v ON_ERROR_STOP=1 -q -d billing -f /demo/seed.sql"
  su postgres -c "pgbackrest stanza-create --log-level-console=warn"
  su postgres -c "pgbackrest backup --start-fast --type=full --log-level-console=warn"
  touch /var/lib/postgresql/data/demo-seeded
fi
touch /tmp/demo-ready
wait "$server"
