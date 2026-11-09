#!/usr/bin/env bash
# macOS (and Linux) run of the plugin transport spike (plugin executables spec 0213, OQ12).
# Expects host and notary-plugin in the current directory.
set -u
failures=()
host=./host
plugin=$PWD/notary-plugin

report() {
	if [ "$2" = 1 ]; then echo "[PASS] $1: $3"; else echo "[FAIL] $1: $3"; failures+=("$1"); fi
}

hostname
uname -a
sw_vers 2>/dev/null || true

for t in unix tcp stdio; do
	echo "== full run, transport $t"
	out=$("$host" -plugin "$plugin" -transport "$t" 2>&1); code=$?
	echo "$out"
	ok=1
	[ "$code" = 0 ] || ok=0
	for want in 'describe ok' 'result ok' 'cancel after first event' 'wrong token refused'; do
		grep -q "$want" <<<"$out" || ok=0
	done
	grep -q FAIL <<<"$out" && ok=0
	if [ "$t" != stdio ]; then grep -q 'plain gRPC client without token: rpc error' <<<"$out" || ok=0; fi
	report "full-$t" "$ok" "exit $code"
done

echo "== plugin run directly"
msg=$("$plugin" </dev/null 2>&1); code=$?
ok=0; [ "$code" = 2 ] && grep -q 'run it through sigillum' <<<"$msg" && ok=1
report direct-run-refused "$ok" "exit $code: $msg"

echo "== plugin with a transport but no token"
msg=$(SPIKE_PLUGIN_TRANSPORT=tcp "$plugin" </dev/null 2>&1); code=$?
ok=0; [ "$code" = 2 ] && grep -q 'run it through sigillum' <<<"$msg" && ok=1
report no-token-refused "$ok" "exit $code: $msg"

for t in unix tcp stdio; do
	echo "== host killed (kill -9), transport $t"
	SPIKE_SLOW=1 "$host" -plugin "$plugin" -transport "$t" >"killed-$t.out" 2>"killed-$t.err" &
	hpid=$!
	sleep 1.5
	child=$(pgrep -P "$hpid" -f notary-plugin | head -1)
	if [ -z "$child" ]; then
		report "killed-host-$t" 0 "no plugin child process found before the kill"
		kill -9 "$hpid" 2>/dev/null; wait "$hpid" 2>/dev/null
		continue
	fi
	kill -9 "$hpid"; wait "$hpid" 2>/dev/null
	gone=0
	for i in $(seq 1 50); do
		if ! kill -0 "$child" 2>/dev/null; then gone=1; break; fi
		sleep 0.1
	done
	if [ "$gone" = 1 ]; then
		report "killed-host-$t" 1 "plugin $child exited within $((i * 100)) ms of the host being killed"
	else
		report "killed-host-$t" 0 "plugin $child still running 5 s after the host was killed"
		kill -9 "$child" 2>/dev/null
	fi
	sed 's/^/  stderr: /' "killed-$t.err"
done

echo "== socket directories left behind in ${TMPDIR:-/tmp} (informational)"
ls -d "${TMPDIR:-/tmp}"/sigillum-plugin-* 2>/dev/null | sed 's/^/  /'
rm -rf "${TMPDIR:-/tmp}"/sigillum-plugin-* 2>/dev/null

if [ "${#failures[@]}" -gt 0 ]; then
	echo "FAILED: ${failures[*]}"
	exit 1
fi
echo "ALL PASS"
