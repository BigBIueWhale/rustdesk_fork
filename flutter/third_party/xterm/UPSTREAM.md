# Vendored xterm

The runtime library, `pubspec.yaml` and MIT `LICENSE` were copied from the
repository's authenticated offline Pub cache for xterm 4.0.0. Its declared
publisher archive SHA-256, also recorded in the former Flutter lockfile, is
`168dfedca77cba33fdb6f52e2cd001e9fde216e398e89335c19b524bb22da3a2`.
The upstream project is <https://github.com/TerminalStudio/xterm.dart>.

The 79 imported files total 344,565 bytes. Their complete path/size/SHA-256
inventory before local changes is retained in
`.harness-state/verifier-vm/xterm-source-import-baeef78c.json` at the repository
root. The license and library files remain byte-identical apart from the
parser-owner change in `lib/src/terminal.dart` and four trailing spaces removed
from key-table lines in `lib/src/core/input/keytab/keytab_default.dart` for the
repository whitespace check. The key-table tokenizer trims each line before
parsing, so those four line-end whitespace changes preserve every binding.

The local change gives `Terminal` one lazily created parser and a
`resetOutputParser()` operation. Stream retirement discards unfinished escape
state without replacing the terminal, clearing the presented screen or changing
callbacks. `TerminalModel` retires that state and unpresented output with its
UTF-8 decoder at open replacement, close and disposal. Parser memory/work bounds
within one live stream remain a separate obligation; reset is not such a bound.

The application's unconditional path dependency selects this reviewed source.
Keep the license, provenance and parser-lifetime behavior when updating it, and
run the focused terminal tests against any replacement.
