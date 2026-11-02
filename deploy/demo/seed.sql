CREATE TABLE public.customers (
    id   bigint PRIMARY KEY,
    name text   NOT NULL
);

CREATE TABLE public.invoices (
    id          bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES public.customers (id),
    amount      numeric(12, 2) NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX invoices_created_at ON public.invoices (created_at);

INSERT INTO public.customers
SELECT g, 'Customer ' || g FROM generate_series(1, 1000) g;

INSERT INTO public.invoices (customer_id, amount, created_at)
SELECT (g % 1000) + 1, (g % 500) + 0.5, now() - interval '30 days' * random()
FROM generate_series(1, 100000) g;

ANALYZE;

CREATE ROLE pol_fingerprint LOGIN PASSWORD 'demo-only';
GRANT CONNECT ON DATABASE billing TO pol_fingerprint;
GRANT USAGE ON SCHEMA public TO pol_fingerprint;
GRANT SELECT ON public.customers, public.invoices TO pol_fingerprint;
