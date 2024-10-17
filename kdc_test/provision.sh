#!/bin/bash

set -xuo pipefail

ln -s /usr/lib64/krb5/plugins/kdb/db2.so /usr/lib64/krb5/plugins/kdb/db2

yes master_password | kdb5_util create -s
yes admin_password | kadmin.local -q "addprinc root/admin"
yes password | kadmin.local -q "addprinc testuser"
yes password | kadmin.local -q "addprinc +requires_preauth testuser_preauth"

kadmin.local -q "addprinc -randkey -policy hosts host/pepper.example.com"
kadmin.local -q "addprinc -randkey -policy hosts host/spot.example.com"

kadmin.local -q "ktadd -k /etc/krb5.keytab host/pepper.example.com"
kadmin.local -q "ktadd -k /etc/krb5.keytab host/spot.example.com"

# Extract all keys to the keytab, useful for decrypt in wireshark
kadmin.local -q "ktadd -norandkey krbtgt/EXAMPLE.COM@EXAMPLE.COM"
kadmin.local -q "ktadd -norandkey testuser@EXAMPLE.COM"
kadmin.local -q "ktadd -norandkey testuser_preauth@EXAMPLE.COM"
kadmin.local -q "ktadd -norandkey host/pepper.example.com@EXAMPLE.COM"
kadmin.local -q "ktadd -norandkey host/spot.example.com@EXAMPLE.COM"
