# LibKrimes

Kerberos is an authentication protocol designed in 1993 before TLS was ubiquitious. It has largely
fallen out of favour due to it's inherent security risks and complexity but a number of ecosystems
have embedded Kerberos deeply in their operation making it sometimes, unavoidable.

This library aims to make a secure-as-possible implementation of a kerberos client and distribution
centre that can be included into other Rust applications.

<p align="center">
  <img src="https://raw.githubusercontent.com/kanidm/libkrimes/master/static/IMG_1775.JPG" width="80%" height="auto" />
</p>

## Cryptography Warning

The current 'state of the art' in Kerberos Cryptography is AES-256-CTS-HMAC-SHA1-96. These are to
put it mildly, not the primitives that any other reasonable modern ecosystem would choose.

While [RFC8009](https://www.rfc-editor.org/rfc/rfc8009) does exist, it should be noted that no KDC
we have tested with supports it in their latest versions (last tested June 2024).

Due to how passwords interact with these primitives in Kerberos, it is *critical* that passwords
are at least 12 characters or more to remain secure against possible bruteforce attacks. We may
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
