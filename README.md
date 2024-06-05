Why.



# Local MIT KRB5 Test Server

```
docker build -f Dockerfile.kdc -t libkrime .
docker run -p 55000:88 -i -t libkrime
```

Password is `password`

```
KRB5_TRACE=/dev/stdout KRB5_CONFIG=krb5.conf /opt/homebrew/opt/krb5/bin/kinit testuser
KRB5_TRACE=/dev/stdout KRB5_CONFIG=krb5.conf /opt/homebrew/opt/krb5/bin/klist
```

```
Ticket cache: FILE:/tmp/krb5cc_501
Default principal: testuser@EXAMPLE.COM

Valid starting       Expires              Service principal
24/05/2024 17:59:57  25/05/2024 03:59:57  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	renew until 31/05/2024 17:59:57
```


