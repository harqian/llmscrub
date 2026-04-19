# llmscrub demo tape — dark theme, real command execution
Output demo-raw.mp4

Set FontSize 18
Set Width 1100
Set Height 640
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 60ms

Hide
Type "clear" Enter
Sleep 300ms
Show

Sleep 600ms
Type "# sweep claude code + codex logs for leaked secrets" Enter
Sleep 700ms
Type "llmscrub scan /tmp/llmscrub-demo-data ~/.claude/projects ~/.codex --fast" Enter
# scan runs ~60s; wait until the summary reveals the detector breakdown.
# "by detector:" is the last line of the pre-list summary — appears once scan finishes.
Sleep 90s

# linger on final summary
Sleep 4s

Type "# now preview what redact would touch" Enter
Sleep 500ms
Type "llmscrub redact --dry-run /tmp/llmscrub-demo-data" Enter
Sleep 4s
