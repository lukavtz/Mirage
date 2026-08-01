#!/bin/sh
set -e
DB="${1:-data/mirage.db}"
DEST="${2:-data/backups}"
mkdir -p "$DEST"
TS=$(date +%Y%m%d_%H%M%S)
cp "$DB" "$DEST/mirage_$TS.db"
ls -t "$DEST"/mirage_*.db | tail -n +8 | xargs -r rm -f   # keep last 7
echo "backup: $DEST/mirage_$TS.db"
