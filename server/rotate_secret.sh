#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run secret rotation with sudo/root." >&2
    exit 1
fi

SECRET_DIR="/etc/myspeedify"
SECRET_FILE="$SECRET_DIR/secret"
SERVICE="myspeedify-server.service"

if [[ -L "$SECRET_DIR" || ! -d "$SECRET_DIR" ]]; then
    echo "Refusing to use a missing or symlinked secret directory: $SECRET_DIR" >&2
    exit 1
fi
if [[ -L "$SECRET_FILE" || ( -e "$SECRET_FILE" && ! -f "$SECRET_FILE" ) ]]; then
    echo "Refusing to replace a non-regular or symlinked secret path: $SECRET_FILE" >&2
    exit 1
fi
if ! id -u myspeedify >/dev/null 2>&1; then
    echo "The myspeedify service account does not exist." >&2
    exit 1
fi
systemctl cat "$SERVICE" >/dev/null

umask 077
temporary_file="$(mktemp "$SECRET_DIR/.secret.XXXXXX")"
trap 'rm -f -- "$temporary_file"' EXIT
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > "$temporary_file"
chown myspeedify:myspeedify "$temporary_file"
chmod 0600 "$temporary_file"
mv -f -- "$temporary_file" "$SECRET_FILE"
trap - EXIT

systemctl restart "$SERVICE"
echo "Secret rotated and relay restarted. Transfer the value in $SECRET_FILE securely to every client."
