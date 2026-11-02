FROM postgres:18
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends pgbackrest >/dev/null \
 && rm -rf /var/lib/apt/lists/*
