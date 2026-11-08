#!/usr/bin/env bash
# Запуск генерации из CSV в отдельный каталог. Действующую сеть не меняет.
set -euo pipefail
cd -- "$(dirname -- "$(realpath -- "$0")")"
OUTPUT="${1:-generated}"
if (( $# > 0 )); then shift; fi
exec python3 ./generate_interfaces.py --input . --output "$OUTPUT" "$@"
