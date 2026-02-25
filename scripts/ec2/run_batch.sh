#!/bin/bash
# Run FORGE on each CVE in a file, one at a time, with process isolation.
# Usage: bash scripts/ec2/run_batch.sh data/config/validation_25.txt
#        bash scripts/ec2/run_batch.sh data/config/batches/batch_01.txt data/config/forge-bedrock.yaml
set -euo pipefail
export PATH=$HOME/.local/bin:$PATH
cd "$(dirname "$0")/../.."

BATCH_FILE="$1"
CONFIG="${2:-data/config/forge-bedrock.yaml}"
BATCH_NAME=$(basename "$BATCH_FILE" .txt)
LOG_DIR="logs"
mkdir -p "$LOG_DIR"

echo "=== Starting batch: $BATCH_NAME (config: $CONFIG) at $(date) ==="

while IFS= read -r cve; do
  [[ -z "$cve" || "$cve" == \#* ]] && continue
  echo "--- Running $cve at $(date) ---"
  uv run forge run "$cve" --config "$CONFIG" 2>&1 | tee "$LOG_DIR/${cve}.log" || {
    echo "FAILED: $cve (exit code $?)"
    continue
  }
  echo "--- Completed $cve at $(date) ---"
done < "$BATCH_FILE"

echo "=== Batch $BATCH_NAME completed at $(date) ==="
