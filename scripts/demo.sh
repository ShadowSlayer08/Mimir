#!/usr/bin/env bash
# scripts/demo.sh — 30-second end-to-end walkthrough script.
#
# Record with:
#   asciinema rec -t "Mimir — 30-second tour" --idle-time-limit 2 \
#     --cols 100 --rows 30 docs/assets/demo.cast -- bash scripts/demo.sh
# Then convert for the README:
#   agg --cols 100 --rows 30 docs/assets/demo.cast docs/assets/demo.gif
#
# Also runnable as a plain script (no recording) to see the full flow fast.

set -euo pipefail

# ---------- UX helpers ---------- #
step() {
    sleep 0.5
    printf "\n\e[1;33m› %s\e[0m\n" "$1"
    sleep 0.8
}
run() {
    printf "\e[0;36m$ %s\e[0m\n" "$*"
    sleep 0.4
    "$@"
}

cd "$(dirname "$0")/.."

step "1 · Verify a clean tree (229/229 tests, KB clean, 7 evals @ 100%)"
run python run_tests.py            # | tail -1 for brevity
run python validate_kb.py          # | tail -1
run python -m evals.bench          # | tail -8

step "2 · Build an engagement from an nmap XML fixture — stage, don't run"
run python assess.py --from-xml tests/fixtures/full_scan.xml --yes \
    --emit-json /tmp/eng.json --report /tmp/report.html \
    --runbook /tmp/runbook.md --enrich --offline

step "3 · Rank the top 5 next-best-actions (co-pilot, offline-safe)"
run python copilot.py /tmp/eng.json --top 5 --why

step "4 · Build a 5-phase recon chain for a domain"
run python recon_chain.py acme.example --phase passive --phase active

step "5 · Pick an adversary emulation profile (Caldera-style)"
run python adversary.py list
run python adversary.py show apt29

step "6 · Serve the read-only engagement viewer (Ctrl-C to stop)"
printf "\n\e[1;33m› mimir-web /tmp/eng.json  —  browse at http://localhost:8787\e[0m\n"
printf "\e[1;33m› mimir-ops                 —  the full operator-workflow web app\e[0m\n"
printf "\n\e[0;32mDone.\e[0m  Repo: github.com/ShadowSlayer08/Mimir\n\n"
