#!/bin/sh
set -eu

project=${COMPOSE_PROJECT_NAME:-panel}
network=${BACKUP_VERIFY_NETWORK:-${project}_default}
volume=${BACKUP_VERIFY_VOLUME:-${project}_panel-backups}
container=${BACKUP_VERIFY_CONTAINER:-${project}-backup-verify}
image=${POSTGRES_IMAGE:-postgres:16-alpine}
user=${POSTGRES_USER:-mirage}
database=${POSTGRES_DB:-mirage}
password=${BACKUP_VERIFY_PASSWORD:-backup-verify-only}

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

dump=$(docker run --rm -v "$volume:/backups:ro" "$image" sh -ec \
	'find /backups -maxdepth 1 -type f -name "mirage-*.dump" -print | sort | tail -n 1')
dump=${dump##*/}
[ -n "$dump" ] || { echo "no backup dump found in $volume" >&2; exit 1; }

docker run -d --name "$container" --network "$network" \
	-e POSTGRES_USER="$user" -e POSTGRES_DB="$database" \
	-e POSTGRES_PASSWORD="$password" "$image" >/dev/null
until docker exec "$container" pg_isready -U "$user" -d "$database" >/dev/null 2>&1; do
	sleep 1
done

docker run --rm --network "$network" -v "$volume:/backups:ro" \
  -e PGPASSWORD="$password" "$image" sh -ec \
  'pg_restore --clean --if-exists --no-owner --exit-on-error \
    --host "$1" --username "$2" --dbname "$3" "/backups/$4"' \
  sh "$container" "$user" "$database" "$dump"

tables=$(docker run --rm --network "$network" -e PGPASSWORD="$password" "$image" \
  psql --host "$container" --username "$user" --dbname "$database" -Atqc \
  "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")
case "$tables" in
  ''|*[!0-9]*) echo "invalid restored table count: $tables" >&2; exit 1 ;;
  0) echo "restore produced no public tables" >&2; exit 1 ;;
esac
printf 'Backup restore verified: %s (%s public tables)\n' "$dump" "$tables"
