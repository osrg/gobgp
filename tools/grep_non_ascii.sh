#!/usr/bin/env bash

# Comments in Go and protobuf sources must use ASCII characters only.
# Typographic characters such as an em dash, an arrow or a section sign are
# hard to type, and they do not survive every terminal, editor and mail
# client. Write "--", "->" and "Section" instead.
#
# The check covers the whole file, not just the comments, because there is no
# cheap way to tell them apart. A string literal that really needs a non-ASCII
# character can use a Go escape sequence, which is ASCII.

SCRIPT_DIR=$(dirname "$0")
cd "${SCRIPT_DIR}/.." || exit 1

# Under LC_ALL=C every byte >= 0x80 is neither printable nor a space, so this
# matches non-ASCII characters and stray control characters. -I skips binary
# files.
if LC_ALL=C git grep -nI '[^[:print:][:space:]]' -- '*.go' '*.proto'; then
    echo
    echo "error: the lines above use non-ASCII characters." >&2
    echo "Go and protobuf sources must be ASCII only." >&2
    exit 1
fi

exit 0
