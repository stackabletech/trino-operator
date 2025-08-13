### Find all truststores in the container

```bash
find / -name '*.p12'
```



keytool -list -storepass changeit -keystore /stackable/server_tls/truststore.p12

openssl pkcs12 -in /etc/pki/java/cacerts -out /tmp/foo.pem -password pass:chageit -legacy
