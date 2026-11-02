#!/bin/sh
set -eu
scale="${1:-1000}"
orders="${2:-20000000}"
psql="psql -X -q -v ON_ERROR_STOP=1 -U postgres -d billing"

pgbench -i -q -s "$scale" -U postgres --foreign-keys billing

$psql <<SQL
CREATE TABLE orders (
  id          bigserial PRIMARY KEY,
  customer_id bigint      NOT NULL,
  created_at  timestamptz NOT NULL,
  status      text        NOT NULL,
  amount      numeric(12,2) NOT NULL,
  note        text,
  payload     jsonb       NOT NULL
);
INSERT INTO orders (customer_id, created_at, status, amount, note, payload)
SELECT (random() * 1000000)::bigint,
       now() - (random() * interval '730 days'),
       (ARRAY['open','paid','shipped','refunded'])[1 + (g % 4)],
       round((random() * 5000)::numeric, 2),
       CASE WHEN g % 7 = 0 THEN md5(g::text) || ' ' || md5((g * 3)::text) END,
       jsonb_build_object('sku', 'SKU-' || (g % 50000), 'qty', 1 + g % 9,
                          'tags', jsonb_build_array('t' || (g % 13), 't' || (g % 17)),
                          'addr', jsonb_build_object('city', 'City ' || (g % 900), 'zip', lpad((g % 99999)::text, 5, '0')))
FROM generate_series(1, $orders) g;
CREATE INDEX orders_created_at ON orders (created_at);
CREATE INDEX orders_customer ON orders (customer_id);
CREATE INDEX orders_payload ON orders USING gin (payload jsonb_path_ops);
ANALYZE;
GRANT SELECT ON pgbench_history, orders TO pol_fingerprint;
SQL
echo "loaded: scale $scale, $orders orders"
