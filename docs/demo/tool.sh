tool() {
  local name="$1" args='{}' kv out
  shift
  for kv in "$@"; do
    args=$(jq -cn --argjson a "$args" --arg k "${kv%%=*}" --arg v "${kv#*=}" '$a + {($k): $v}')
  done
  out=$({
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}'
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    jq -cn --arg n "$name" --argjson a "$args" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:$n,arguments:$a}}'
    sleep 0.6
  } | opsgate serve 2>/dev/null | jq -r 'select(.id==2) | if .error then "x protocol error: " + .error.message elif .result.isError then "x " + .result.content[0].text else "v " + .result.content[0].text end')
  case "$out" in
    x*) printf '\033[31m  ✗ %s\033[0m\n\n' "$(printf '%s' "${out#x }" | fold -s -w 96 | sed '2,$s/^/    /')" ;;
    *) printf '\033[32m  ✓\033[0m %s\n\n' "$(printf '%s' "${out#v }" | head -6 | fold -s -w 96 | sed '2,$s/^/    /')" ;;
  esac
}
