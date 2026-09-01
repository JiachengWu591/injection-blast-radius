#!/usr/bin/env bash
# Put mise on the PATH, then let mise do everything else.
#
# A separate file rather than a long postCreateCommand string, because a
# multi-command shell one-liner inside JSON is where the unreadable quoting
# mistake goes, and because this way it can be run by hand on a machine that is
# not a Codespace.
set -euo pipefail

if ! command -v mise >/dev/null 2>&1; then
    curl -fsSL https://mise.run | sh
fi

MISE="${HOME}/.local/bin/mise"
[ -x "$MISE" ] || MISE="$(command -v mise)"

# Activate mise for future interactive shells. Guarded, because appending
# unconditionally would stack up one line per container rebuild.
if [ -f "${HOME}/.bashrc" ] && ! grep -q 'mise activate' "${HOME}/.bashrc"; then
    echo 'eval "$(mise activate bash)"' >> "${HOME}/.bashrc"
fi
if [ -f "${HOME}/.zshrc" ] && ! grep -q 'mise activate' "${HOME}/.zshrc"; then
    echo 'eval "$(mise activate zsh)"' >> "${HOME}/.zshrc"
fi

# mise refuses to run a config file it has not been told to trust. That default
# is right — a config file can run commands — and this is the one place where
# answering "yes" is unambiguous, because the user just opened this repository
# on purpose.
"$MISE" trust
"$MISE" install

# Warm the venv so the first `mise run demo` is just the demo.
"$MISE" run setup

cat <<'EOF'

Ready. Try:

    mise run demo        the whole comparison, from recorded exchanges
    mise run test        the offline assertions
    mise tasks           everything else

`mise run demo` needs no API key. Set DEEPSEEK_API_KEY only if you want
`mise run demo:live`, which calls the real model and costs money.
EOF
