#!/bin/bash
# ============================================================================
# FORGE Autonomous Evaluation Orchestrator
# ============================================================================
# Runs all 24 batches sequentially with:
#   - Podman cleanup between batches (preserves SearXNG + exploit-runner)
#   - Automated health checks (crash rate, cost, disk, knowledge growth)
#   - Auto-stop on any stop condition failure
#   - Batch tracking JSON for dashboard consumption
#
# Usage:
#   bash scripts/ec2/run_evaluation.sh                                       # defaults
#   bash scripts/ec2/run_evaluation.sh data/config/forge-bedrock.yaml 01     # start from batch 01
#   bash scripts/ec2/run_evaluation.sh data/config/forge-bedrock.yaml 05     # resume from batch 05
#
# Prerequisites:
#   - Batch files exist: data/config/batches/batch_01.txt through batch_24.txt
#   - Config file exists
#   - SearXNG container running
#   - forge-exploit-runner image present
#   - data/analysis/ directory writable
# ============================================================================
set -euo pipefail
export PATH=$HOME/.local/bin:$PATH
cd "$(dirname "$0")/../.."

CONFIG="${1:-data/config/forge-bedrock.yaml}"
START_BATCH="${2:-01}"
TOTAL_BATCHES=24
TRACKING_FILE="data/analysis/batch_tracking.json"
LOG_DIR="logs"

mkdir -p data/analysis "$LOG_DIR"

echo "============================================================"
echo "FORGE CVE Evaluation"
echo "  Config:       $CONFIG"
echo "  Start batch:  $START_BATCH"
echo "  Tracking:     $TRACKING_FILE"
echo "  Started at:   $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"

# Verify prerequisites
if [ ! -f "$CONFIG" ]; then
    echo "ERROR: Config file not found: $CONFIG"
    exit 1
fi

if ! podman images | grep -q forge-exploit-runner; then
    echo "ERROR: forge-exploit-runner image not found"
    exit 1
fi

# Check SearXNG is running
if ! podman ps --format '{{.Names}}' 2>/dev/null | grep -qi searx; then
    echo "WARNING: SearXNG container not detected. Web search will fall back to DDG."
fi

# ── Podman cleanup function ─────────────────────────────────────────────────
podman_cleanup() {
    echo "--- Podman cleanup ---"

    # Stop and remove all containers EXCEPT SearXNG
    for cid in $(podman ps -aq 2>/dev/null); do
        name=$(podman inspect --format '{{.Name}}' "$cid" 2>/dev/null || echo "")
        # Preserve SearXNG container (match various naming conventions)
        if echo "$name" | grep -qi "searx"; then
            echo "  Keeping container: $name ($cid)"
            continue
        fi
        podman rm -f "$cid" 2>/dev/null || true
    done

    # Remove generated app images (keep base images, exploit-runner, SearXNG image)
    podman images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | \
        grep -vE '(python|node|openjdk|golang|php|ruby|rust|maven|gradle|composer|forge-exploit-runner|searx|<none>)' | \
        awk '{print $2}' | xargs -r podman rmi -f 2>/dev/null || true

    # Prune dangling images and build cache
    podman image prune -f 2>/dev/null || true
    podman builder prune -f 2>/dev/null || true

    # Clean temp build dirs
    rm -rf /tmp/forge-forge-cve-*

    echo "  Disk free: $(df -h . | tail -1 | awk '{print $4}')"
    echo "  Containers running: $(podman ps -q 2>/dev/null | wc -l | tr -d ' ')"
}

# ── Main batch loop ─────────────────────────────────────────────────────────
for batch_int in $(seq "$START_BATCH" $TOTAL_BATCHES); do
    BATCH_NUM=$(printf '%02d' "$batch_int")
    BATCH_FILE="data/config/batches/batch_${BATCH_NUM}.txt"

    if [ ! -f "$BATCH_FILE" ]; then
        echo "Batch file $BATCH_FILE not found — skipping."
        continue
    fi

    CVE_COUNT=$(grep -cv '^$\|^#' "$BATCH_FILE" 2>/dev/null || true)

    echo ""
    echo "============================================================"
    echo "BATCH $BATCH_NUM ($CVE_COUNT CVEs) — $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "============================================================"

    # Step 1: Podman cleanup (skip for first batch since Phase 0.3 handles it)
    if [ "$batch_int" -gt "$START_BATCH" ] || [ "$START_BATCH" != "01" ]; then
        podman_cleanup
    fi

    # Step 2: Run the batch
    echo "--- Running batch $BATCH_NUM ---"
    bash scripts/ec2/run_batch.sh "$BATCH_FILE" "$CONFIG" 2>&1 | tee "$LOG_DIR/batch_${BATCH_NUM}.log"

    echo "--- Batch $BATCH_NUM execution finished at $(date -u '+%Y-%m-%d %H:%M:%S UTC') ---"

    # Step 3: Health check (|| true prevents set -e from aborting before we read $?)
    echo "--- Running health check for batch $BATCH_NUM ---"
    python3 scripts/analysis/batch_health_check.py \
        --batch-num "$BATCH_NUM" \
        --batch-file "$BATCH_FILE" \
        --results-dir data/results \
        --knowledge-dir data/knowledge \
        --tracking-file "$TRACKING_FILE" \
    || HEALTH_EXIT=$?

    HEALTH_EXIT=${HEALTH_EXIT:-0}

    if [ "$HEALTH_EXIT" -ne 0 ]; then
        echo ""
        echo "============================================================"
        echo "EVALUATION STOPPED — Batch $BATCH_NUM health check FAILED"
        echo "See $TRACKING_FILE for details."
        echo "Stopped at: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "============================================================"
        exit 1
    fi

    echo "--- Batch $BATCH_NUM PASSED health check ---"
done

echo ""
echo "============================================================"
echo "EVALUATION COMPLETE — All $TOTAL_BATCHES batches processed"
echo "Tracking file: $TRACKING_FILE"
echo "Finished at: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
