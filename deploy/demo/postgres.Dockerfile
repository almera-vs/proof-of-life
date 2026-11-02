ARG PG_MAJOR=17
FROM postgres:${PG_MAJOR}
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends pgbackrest openssl >/dev/null \
 && rm -rf /var/lib/apt/lists/*
COPY demo-entrypoint.sh /usr/local/bin/demo-entrypoint.sh
COPY seed.sql /demo/seed.sql
RUN chmod 0755 /usr/local/bin/demo-entrypoint.sh
