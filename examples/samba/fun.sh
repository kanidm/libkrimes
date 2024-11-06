#!/usr/bin/env bash

# Exit if any error
set -euox pipefail

echo "password" | kinit krime
klist -f /tmp/krb5cc_${UID}
smbclient //samba.example.com/test --use-kerberos=required --use-krb5-ccache=/tmp/krb5cc_${UID}
