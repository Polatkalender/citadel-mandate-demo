# Reproducible terminal cast for the README hero.
#
# Render:  vhs demo.tape      ->  writes docs/demo.gif
# Install: https://github.com/charmbracelet/vhs  (needs ttyd + ffmpeg)
#
# The build is done hidden so the cast shows only the demo output.

Output docs/demo.gif

Set Shell bash
Set FontSize 20
Set Width 1180
Set Height 640
Set Padding 20
Set Theme "Dracula"
Set PlaybackSpeed 1.0

# --- build off-camera so the cast is just the run ---
Hide
Type "cargo build --release" Enter
Wait
Type "clear" Enter
Show

# --- the 30-second money shot ---
Type "./target/release/citadel-mandate-demo" Sleep 400ms Enter
Wait
Sleep 4s
