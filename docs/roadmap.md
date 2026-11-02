# Roadmap

Out of scope for v1. The interfaces in `internal/source` and `internal/sandbox` are kept small so these can be added later.

- WAL-G and Barman sources.
- RDS and Cloud SQL snapshot sources.
- MySQL and other engines.
- Kubernetes-native sandboxes.
- A hosted dashboard across many databases, built from the run report JSON.
- A web UI.
- An internal scheduler daemon. Scheduling stays with cron, systemd timers and Kubernetes CronJobs.
- Multi-tenancy.
