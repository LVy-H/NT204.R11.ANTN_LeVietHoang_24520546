#!/bin/sh
# Regenerates case results. No argument: every TEST/*/fixtures/* file.
# Arguments: fixture paths relative to the repository root.
set -eu
cd "$(dirname "$0")/.."

PYTHON=${PYTHON:-.venv/bin/python}
if [ ! -x "$PYTHON" ]; then
    PYTHON=python3
fi

flows=no
if "$PYTHON" main.py --help | grep -q -- --flows-output; then
    flows=yes
fi

if [ "$#" -eq 0 ]; then
    set -- TEST/*/fixtures/*
fi

for fixture in "$@"; do
    [ -f "$fixture" ] || continue
    group=$(dirname "$(dirname "$fixture")")
    base=$(basename "$fixture")
    name=${base%.*}
    case "$base" in
        *.pcap | *.pcapng) input="--pcap $fixture" ;;
        *.jsonl) input="--events $fixture" ;;
        *) continue ;;
    esac
    case "$name" in
        [0-9]*) case_dir="$group/case-$name" ;;
        *) case_dir="$group/$name" ;;
    esac
    mkdir -p "$case_dir"
    command="$PYTHON main.py $input --output $case_dir/output.jsonl"
    if [ "$flows" = yes ]; then
        command="$command --flows-output $case_dir/flows.jsonl"
    fi
    command="$command --stats"
    printf '%s\n' "$command" > "$case_dir/command.txt"
    sh -c "$command" > "$case_dir/stdout.txt" 2> "$case_dir/summary.txt"
    records=$(awk 'END{print NR}' "$case_dir/output.jsonl")
    printf '%-40s records=%s\n' "$case_dir" "$records"
done
