#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."

limit=900
start=$(date +%s)
mapfile -t commands < <(awk '
  /^## Quick start/ { inside = 1 }
  /^## Setting up a drill/ { inside = 0 }
  inside && /^```bash$/ { block = 1; next }
  inside && /^```$/ { block = 0; next }
  inside && block { print }
' README.md)

if [ "${#commands[@]}" -lt 8 ]; then
  echo "found only ${#commands[@]} commands in the README" >&2
  exit 1
fi

fail() { echo "QUICKSTART FAILED: $1" >&2; exit 1; }

drills=0
broken=0
for cmd in "${commands[@]}"; do
  echo "\$ $cmd"
  out=$(bash -c "$cmd" 2>/tmp/quickstart.err)
  code=$?
  echo "$out" | tail -4
  case "$cmd" in
    *" run --rm break"*)
      broken=1
      [ "$code" -eq 0 ] || fail "the break step exited $code"
      ;;
    *" pol run "*)
      drills=$((drills + 1))
      if [ "$broken" -eq 0 ]; then
        [ "$code" -eq 0 ] || { tail -5 /tmp/quickstart.err >&2; fail "the drill exited $code, want 0"; }
        grep -q 'RESTORABLE' <<<"$out" && grep -q '12/12 checks' <<<"$out" || fail "the drill did not report RESTORABLE 12/12"
        echo "first passing drill after $(($(date +%s) - start))s"
      else
        [ "$code" -eq 1 ] || fail "the broken drill exited $code, want 1"
        grep -q 'NOT RESTORABLE' <<<"$out" || fail "the broken drill did not report NOT RESTORABLE"
      fi
      ;;
    *" run --rm reports"*)
      [ "$code" -eq 0 ] || fail "copying reports exited $code"
      ls deploy/demo/out/*.html >/dev/null 2>&1 || fail "no HTML report was copied out"
      ;;
    *)
      [ "$code" -eq 0 ] || { tail -5 /tmp/quickstart.err >&2; fail "exit $code"; }
      ;;
  esac
done

[ "$drills" -eq 2 ] || fail "expected 2 drills in the README, ran $drills"
total=$(($(date +%s) - start))
echo "quickstart finished in ${total}s"
[ "$total" -le "$limit" ] || fail "took ${total}s, over the 15 minute promise"
