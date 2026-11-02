#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out=THIRD_PARTY_NOTICES.txt
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for target in linux/amd64 linux/arm64 windows/amd64; do
  CGO_ENABLED=0 GOOS="${target%/*}" GOARCH="${target#*/}" go build -o "$tmp/pol" ./cmd/pol
  go version -m "$tmp/pol" | awk '$1 == "dep" { print $2, $3 }'
done | sort -u > "$tmp/modules"

modcache=$(go env GOMODCACHE)
{
  echo "Third-party software in Proof of Life"
  echo
  echo "pol is built with the Go toolchain, and includes the modules listed below."
  echo "Each module's licence follows, as published by its authors."
  echo
  echo "Go standard library and runtime: BSD-3-Clause, Copyright The Go Authors."
  echo
  while read -r module version; do
    escaped=$(printf '%s' "$module" | sed -E 's/([A-Z])/!\L\1/g')
    dir="$modcache/$escaped@$version"
    echo "================================================================================"
    echo "$module $version"
    echo "================================================================================"
    found=0
    for name in LICENSE LICENSE.md LICENSE.txt LICENCE COPYING NOTICE NOTICE.md; do
      if [ -f "$dir/$name" ]; then
        echo
        cat "$dir/$name"
        echo
        found=1
      fi
    done
    if [ "$found" -eq 0 ]; then
      echo "No licence file was found in the module; see https://pkg.go.dev/$module"
    fi
    echo
  done < "$tmp/modules"
} > "$out"
echo "wrote $out with $(wc -l < "$tmp/modules") modules"
