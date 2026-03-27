This application was used to produce the `delta-table` for the delta kuttl test.

It cannot be placed in the delta test folder because beku tries to recurse into it and fails.

To run it, you need a S3 (minio) available. Update the variables below as needed:

    S3_ENDPOINT=https://localhost:9000 \
    S3_ACCESS_KEY=minioAccessKey \
    S3_SECRET_KEY=minioSecretKey \
    S3_SKIP_TLS_VALIDATION=true \
    DELTA_TABLE_PATH=s3a://trino/delta-table \
    ./gradlew run
