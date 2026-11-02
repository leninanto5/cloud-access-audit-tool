#!/bin/sh
# Runs the audit with the demo data (Linux / Mac). Add your own options after the command.
cd "$(dirname "$0")/.." || exit 1
python3 audit_report.py --demo "$@"
