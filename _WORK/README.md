
### Create problem

```bash
stackablectl op in commons listener secret trino
kind load docker-image oci.stackable.tech/sdp/trino:476-stackable0.0.0-dev-with-merger
kubectl apply -f _WORK/trino.yaml
```
The Trino Pod will not came up because of `backend failed to get secret data: failed to pick a CA: no CA in Secret.v1./secret-provisioner-short-tls-ca.stackable-operators will live until at least 2025-09-04 8:03:42.030007063 +00:00:00`.
That's totally expected!

Let's wait until the CA certificate Secrets have the desired amount of rotated certificates.

Afterwards increase the ca cert lifetime to start the Pod:

```bash
kubectl patch secretclass short-tls --type=merge --patch '{"spec": {"backend": {"autoTls": {"ca": {"caCertificateLifetime": "365d"}}}}}'
```

Congrats, your secret-op now did a certificate rotation and your Pod should start up (after some time for retries)!

### Debug commands

```bash
keytool -list -storepass "" -keystore /certs/pkcs12-1/truststore.p12
openssl pkcs12 -password pass: -in /certs/pkcs12-1/truststore.p12
```
