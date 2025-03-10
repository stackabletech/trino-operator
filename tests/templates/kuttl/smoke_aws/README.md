# Smoke test with AWS S3

This is a variation to the plain smoke tests which use Minio.

## Setup a Bucket

...and load data into it:

```shell
BUCKET_NAME="my-bucket"
aws s3api create-bucket --bucket ${BUCKET_NAME} --region eu-central-1 --create-bucket-configuration LocationConstraint=eu-central-1
aws s3 cp yellow_tripdata_2021-07.csv s3://${BUCKET_NAME}/taxi-data/
```

You will need to update the bucket name in [check-s3.py](check-s3.py).

## Add AWS credentials

The user or role that the access key belongs to needs to have read/write access to the S3 bucket.

Update [aws_secret.yaml](./aws_secret.yaml), and apply it to the cluster:

```shell
kubectl apply -f aws_secret.yaml
```

## Run the tests

Add a new test definition to [test-definition.yaml](/tests/test-definition.yaml).

```yaml
tests:
  - name: smoke_aws
    dimensions:
      - trino
      - hive
      - opa
      - hdfs
      - zookeeper
      - openshift
```

Then run a tests:

```sh
./scripts/run-tests --test smoke_aws
```
