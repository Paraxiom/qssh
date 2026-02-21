#!/bin/bash
set -e

# QSSH Docker entrypoint
# Provisions user home directories from /etc/qssh/authorized_keys
# and generates host keys if missing, then starts qsshd.

KEYS_FILE="/etc/qssh/authorized_keys"
HOST_KEY="/etc/qssh/host_key"

# Generate host keys if they don't exist or are empty stubs
if [ ! -f "$HOST_KEY" ] || [ ! -s "$HOST_KEY" ] || grep -q "^#" "$HOST_KEY" 2>/dev/null; then
    echo "Generating host keys..."
    /usr/local/bin/qsshd --generate-keys --host-key "$HOST_KEY"
fi

# Provision user home directories from authorized_keys
if [ -f "$KEYS_FILE" ]; then
    echo "Provisioning users from $KEYS_FILE..."
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue

        # Two authorized_keys formats supported:
        # 1. Standard: qssh-falcon512 <base64-key> user@host
        # 2. QSSH:    username qssh-falcon512 <base64-key>
        first_field=$(echo "$line" | awk '{print $1}')

        if [[ "$first_field" == qssh-* ]]; then
            # Standard format — extract username from comment (user@host)
            username=$(echo "$line" | awk '{print $NF}' | cut -d@ -f1)
        else
            # QSSH format — first field is username
            username="$first_field"
        fi

        # Skip if we couldn't extract a username
        if [ -z "$username" ] || [ "$username" = "*" ]; then
            continue
        fi

        # Create home directory structure
        user_home="/home/$username"
        user_qssh="$user_home/.qssh"

        if [ ! -d "$user_qssh" ]; then
            echo "Creating home directory for user: $username"
            mkdir -p "$user_qssh"
        fi

        # Create per-user authorized_keys if it doesn't exist
        user_keys="$user_qssh/authorized_keys"
        if [ ! -f "$user_keys" ]; then
            echo "Provisioning authorized_keys for user: $username"
            # Extract all keys for this user
            grep -E "(^qssh-.*${username}|^${username}[[:space:]])" "$KEYS_FILE" > "$user_keys" 2>/dev/null || true
        fi

    done < "$KEYS_FILE"
    echo "User provisioning complete."
else
    echo "Warning: No authorized_keys file at $KEYS_FILE"
fi

# Ensure log directory exists
mkdir -p /var/log/qssh

# Exec qsshd with any passed arguments
exec /usr/local/bin/qsshd "$@"
