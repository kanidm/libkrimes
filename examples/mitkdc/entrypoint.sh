#!/usr/bin/env bash

# Exit if any error
set -euo pipefail

if [ "$1" == "mitkdc" ]; then
    sed -i 's/55000/88/' /etc/krb5.conf
    echo "Starting KDC..."
    /usr/sbin/krb5kdc -n
else
    eval "$1"
    exit 0
fi
