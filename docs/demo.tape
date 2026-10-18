Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 500
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Hide
Type `source docs/demo/tool.sh && export HOME="$(mktemp -d)" && cd "$HOME" && mkdir .opsgate && printf 'mode: observe\nfiles:\n  allow_paths: [/var/log]\naudit:\n  path: audit.jsonl\n' > .opsgate/config.yaml && clear` Enter
Sleep 500ms
Show

Type "# an AI agent gets typed tools from opsgate, not a shell. Let it try to break things:" Enter Sleep 1s
Type `tool service_status name="nginx; touch /tmp/pwned"` Enter Sleep 2.5s
Type `tool file_read path=/var/log/../../etc/shadow` Enter Sleep 2.5s
Type `tool service_restart name=nginx` Enter Sleep 2.5s
Type "# nothing ran:" Enter Sleep 500ms
Type "ls /tmp/pwned" Enter Sleep 2s
Type "# and every attempt is on the record, hash-chained:" Enter Sleep 500ms
Type `jq -r '"#\(.seq)  \(.decision)  \(.tool)  hash=\(.hash[:16])..."' audit.jsonl` Enter Sleep 3s
Type "opsgate audit verify" Enter Sleep 4s
