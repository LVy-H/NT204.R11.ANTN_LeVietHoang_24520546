#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

PYTHON=${PYTHON:-.venv/bin/python}
if [ ! -x "$PYTHON" ]; then
    PYTHON=python3
fi

for fixture in TEST/fixtures/*; do
    base=$(basename "$fixture")
    name=${base%.*}
    case_dir="TEST/case-$name"
    mkdir -p "$case_dir"
    command="$PYTHON main.py --pcap $fixture --output $case_dir/output.jsonl --stats"
    printf '%s\n' "$command" > "$case_dir/command.txt"
    sh -c "$command" > "$case_dir/stdout.txt" 2> "$case_dir/summary.txt"
    events=$(awk 'END{print NR}' "$case_dir/output.jsonl")
    printf '%-32s events=%s\n' "$case_dir" "$events"
done
