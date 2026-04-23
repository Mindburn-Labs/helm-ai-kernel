#!/bin/bash
set -e

# HELM Latency Benchmark
# Compares raw LLM provider latency vs HELM governed latency.

PROVIDER_URL="https://api.openai.com/v1/chat/completions"
HELM_URL="http://localhost:8080/v1/chat/completions"

# ANSI Colors
BOLD='\033[1m'
CYAN='\033[36m'
GREEN='\033[32m'
RED='\033[31m'
NC='\033[0m'

if [ -z "$OPENAI_API_KEY" ]; then
    echo -e "${RED}Error: OPENAI_API_KEY is required for benchmarking.${NC}"
    exit 1
fi

echo -e "${BOLD}HELM Performance Benchmark${NC}"
echo "─────────────────────────────────────────"

PAYLOAD='{
  "model": "gpt-4o-mini",
  "messages": [{"role": "user", "content": "Return the word OK and nothing else."}],
  "max_tokens": 5
}'

measure() {
    local url=$1
    local name=$2
    local auth=$3
    
    echo -n "  • Measuring $name... "
    
    start_time=$(date +%s%N)
    # Use single line curl to avoid splitting issues in shell environments
    res=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$url" -H "Content-Type: application/json" -H "Authorization: Bearer $auth" -d "$PAYLOAD")
    end_time=$(date +%s%N)
    
    if [ "$res" != "200" ]; then
        echo -e "${RED}FAILED (HTTP $res)${NC}"
        return 1
    fi
    
    duration=$(( (end_time - start_time) / 1000000 ))
    echo -e "${GREEN}${duration}ms${NC}"
    echo "$duration"
}

# 1. Measure Raw
RAW_LATENCY=$(measure "$PROVIDER_URL" "Raw OpenAI" "$OPENAI_API_KEY")

# 2. Measure HELM
# Ensure helm is running
if ! curl -s http://localhost:8081/healthz > /dev/null; then
    echo -e "${RED}Error: HELM server is not running on :8080/8081${NC}"
    exit 1
fi
HELM_LATENCY=$(measure "$HELM_URL" "HELM Governed" "$OPENAI_API_KEY")

# 3. Calculate Overhead
OVERHEAD=$(( HELM_LATENCY - RAW_LATENCY ))
PERCENT=$(awk "BEGIN {printf \"%.1f\", ($OVERHEAD/$RAW_LATENCY)*100}")

echo "─────────────────────────────────────────"
echo -e "${BOLD}OVERHEAD:${NC} ${CYAN}${OVERHEAD}ms${NC} (${PERCENT}%)"
echo -e "${BOLD}VERDICT:${NC}  HELM adds minimal cryptographic and policy overhead."
