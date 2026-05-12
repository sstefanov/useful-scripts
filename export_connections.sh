#!/bin/bash

set -euo pipefail

EXPORT_DIR="$HOME/nm-wallet-export"
TMPDIR=$(mktemp -d)

mkdir -p "$EXPORT_DIR/connections"
mkdir -p "$EXPORT_DIR/secrets"

echo "=== Copying NetworkManager connection files ==="

sudo cp /etc/NetworkManager/system-connections/* \
    "$TMPDIR"/ 2>/dev/null || true

sudo chown "$USER":"$USER" \
    "$TMPDIR"/* 2>/dev/null || true

echo
echo "=== Exporting KWallet NetworkManager secrets ==="

kwallet-query kdewallet \
    -f "Network Management" \
    -l | while read -r entry; do

    [ -n "$entry" ] || continue

    echo
    echo "Processing wallet entry:"
    echo "  $entry"

    # Extract UUID from:
    # {UUID};something

    uuid=$(echo "$entry" \
        | sed -n 's/^{\([^}]*\)};.*/\1/p')

    if [ -z "$uuid" ]; then
        echo "  Cannot extract UUID, skipping"
        continue
    fi

    # Safe filename

    safe=$(echo "$entry" \
        | sed 's#[{};/ ]#_#g')

    # Export wallet secret

    kwallet-query kdewallet \
        -f "Network Management" \
        -r "$entry" \
        > "$EXPORT_DIR/secrets/$safe.secret"

    echo "$entry" \
        > "$EXPORT_DIR/secrets/$safe.entryname"

    # Find matching connection file

    found=0

    for f in "$TMPDIR"/*; do

        [ -f "$f" ] || continue

        if grep -q "^uuid=$uuid$" "$f"; then

            base=$(basename "$f")

            echo "  Found connection:"
            echo "    $base"

            cp -n "$f" \
                "$EXPORT_DIR/connections/"

            found=1
        fi
    done

    if [ "$found" -eq 0 ]; then
        echo "  WARNING: no connection file found"
    fi
done

rm -rf "$TMPDIR"

echo
echo "=== Export complete ==="
echo
echo "Files stored in:"
echo "  $EXPORT_DIR"
