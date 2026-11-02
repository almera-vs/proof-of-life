CREATE TABLE public.pol_heartbeat (ts timestamptz NOT NULL);
CREATE INDEX pol_heartbeat_ts ON public.pol_heartbeat (ts);

CREATE ROLE pol_heartbeat LOGIN PASSWORD 'change-me'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
GRANT CONNECT ON DATABASE billing TO pol_heartbeat;
GRANT USAGE ON SCHEMA public TO pol_heartbeat;
GRANT SELECT, INSERT, DELETE ON public.pol_heartbeat TO pol_heartbeat;
