#!/usr/bin/env bash
# usage: timing_helper.sh <case> <arm> <tokens> <ms>
d=/home/user/RootkitResearch/skills/sentinel-fp-workflow-workspace/iteration-1/$1/$2; mkdir -p "$d"
python3 -c "import json,sys; t=int(sys.argv[1]); ms=int(sys.argv[2]); json.dump({'total_tokens':t,'duration_ms':ms,'total_duration_seconds':round(ms/1000,1)}, open('$d/timing.json','w'), indent=2)" "$3" "$4"
echo "$1/$2: $3 tokens, $4 ms"
