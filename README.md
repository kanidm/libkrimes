# LibKrimes

Kerberos is an authentication protocol designed in 1993 before TLS was ubiquitious. It has largely
fallen out of favour due to it's inherent security risks and complexity, but a number of ecosystems
have embedded Kerberos deeply in their operation making it sometimes, unavoidable.

This library aims to make a secure-as-possible implementation of a kerberos client and distribution
centre that can be included into other Rust applications.

<p align="center">
  <img src="https://raw.githubusercontent.com/kanidm/libkrimes/master/static/IMG_8786.JPG" width="80%" height="auto" />
</p>

## Cryptography Warning

As Kerberos chooses the *strongest* cryptographic method that is shared between the client and KDC,
then a malicious client is able to choose the *weakest* option from that
selection and attack it. This means that even if you offered password authenticated key exchange (PAKE)
methods, the existence of RC4-HMAC in your KDC completely undermines this. Because of this, we must
judge Kerberos implementations by the minimums they offer, and the maximums they can consume.

Navigating this complexity, the current 'state of the art' minimum in Kerberos between operating
systems is AES-256-CTS-HMAC-SHA1-96. This is not the primitives that any other reasonable modern
ecosystem would choose.

While stronger methods like [RFC8009](https://www.rfc-editor.org/rfc/rfc8009) do exist, it should be
noted that no KDC we have tested with supports it in their latest versions (last tested June 2024)
by default, and even if it *was* enabled, AES-256-CTS-HMAC-SHA1-96 is still the global default
minimum that all clients and servers need to offer and support.

Because of this, we need to attempt to make AES-256-CTS-HMAC-SHA1-96 reasonably secure. There are a
number of ways libkrimes will achieve this, but a major one is password length.

Due to how passwords interact with these primitives in Kerberos, it is *critical* that passwords
are at least 16 characters or more to remain secure against possible bruteforce attacks. We may
change this advice in future.

## Intentional Design Limits

To remain secure (as is a major goal in the Kanidm ecosystem) we plan to impose limits on how Kerberos
can function in this library to limit potential risks. These limits are to be decided in future.

## Local MIT KRB5 Test Server

This builds a localhost KRB5 KDC that can be used as a reference for some protocol tests until we
are able to self-host these internally in the library.

```sh
docker build -f Dockerfile.kdc -t libkrime .
docker run --rm -e KRB5_TRACE=/dev/stderr -p 55000:88 -i -t libkrime
```

Generally the logging from the KDC is poor at best and probably won't help you much.

Password is `password`

```sh
KRB5_TRACE=/dev/stdout KRB5_CONFIG=kdc_test/krb5.conf /opt/homebrew/opt/krb5/bin/kinit testuser
KRB5_TRACE=/dev/stdout KRB5_CONFIG=kdc_test/krb5.conf /opt/homebrew/opt/krb5/bin/klist
```

```
Ticket cache: FILE:/tmp/krb5cc_501
Default principal: testuser@EXAMPLE.COM

Valid starting       Expires              Service principal
24/05/2024 17:59:57  25/05/2024 03:59:57  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	renew until 31/05/2024 17:59:57
```

You can run the test suite with:

```
cargo test
```

If you host the docker container on another address, you can instruct the test suite to use this with:

```
LIBKRIMES_TEST_KDC_ADDRESS=127.0.0.1:55000 cargo test
```

## KrimeDC Testing

Run the KrimeDC:

```
$ cargo run --bin krimedc run $(pwd)/examples/krime.conf
```

Test with system's MIT client:

```
$ KRB5_TRACE=/dev/stdout KRB5_CONFIG=$(pwd)/kdc_test/krb5.conf kinit testuser@EXAMPLE.COM

$ klist -c /tmp/krb5cc_1000
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: testuser@EXAMPLE.COM

Valid starting     Expires            Service principal
03/10/24 12:41:18  03/10/24 16:41:18  krbtgt/EXAMPLE.COM@EXAMPLE.COM
        renew until 10/10/24 12:41:15

```

Test with MIT container:

```
$ docker run --rm -it --network=host libkrime kinit testuser@EXAMPLE.COM && klist -c /tmp/krb5cc_1000
Password for testuser@EXAMPLE.COM:

Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: testuser@EXAMPLE.COM

Valid starting     Expires            Service principal
03/10/24 12:33:34  03/10/24 16:33:34  krbtgt/EXAMPLE.COM@EXAMPLE.COM
        renew until 10/10/24 12:33:33

```

## Getting A Service Keytab

```
$ cargo run --bin krimedc keytab $(pwd)/examples/krime.conf HOST/localhost /tmp/keytab
```

```
$ KRB5_TRACE=/dev/stdout KRB5_CONFIG=$(pwd)/kdc_test/krb5.conf klist -e -k /tmp/keytab

Keytab name: FILE:/tmp/key
KVNO Principal
---- --------------------------------------------------------------------------
   2 HOST/localhost@EXAMPLE.COM (aes256-cts-hmac-sha1-96)
```

## Testing A Service Request


```
$ KRB5_TRACE=/dev/stdout KRB5_CONFIG=$(pwd)/kdc_test/krb5.conf kvno HOST/localhost
```

## NOTES:

* MacOS will only use kerberos to an SMB share, if the SMB share is discovered via avahi/bonjour.


## Run samba krb5 testsuite

Run the KrimeDC:

```
$ cargo run --bin krimedc run $(pwd)/examples/krime.conf
```

Run the samba tests:

```
```
SERVER="127.0.0.1:55000" DC_SERVER="127.0.0.1:55000" DOMAIN="EXAMPLE" REALM="EXAMPLE.COM" CLIENT_USERNAME="testuser" CLIENT_PASSWORD="a-secure-password" SERVICE_USERNAME="cifs" SERVICE_PASSWORD="a-secure-password" KRBTGT_KVNO=1 KRBTGT_AES256_KEY_HEX="db8bcc6e7a9ae76d720fda34ce1c7f222529f8550df7176eda2c22ffcfa6e478" ADMIN_USERNAME="administrator" ADMIN_PASSWORD="a-secure-password" SMB_CONF_PATH="/etc/samba/smb.conf" python3 python/samba/tests/krb5/kdc_tgt_tests.py
```
```

