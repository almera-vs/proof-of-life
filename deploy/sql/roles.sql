CREATE ROLE pol_fingerprint LOGIN PASSWORD 'change-me'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
ALTER ROLE pol_fingerprint SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE billing TO pol_fingerprint;
GRANT USAGE ON SCHEMA public TO pol_fingerprint;
GRANT SELECT ON public.invoices, public.customers TO pol_fingerprint;
GRANT pg_read_all_stats TO pol_fingerprint;
