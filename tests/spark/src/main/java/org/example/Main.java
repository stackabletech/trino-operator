package org.example;

import org.apache.spark.sql.SparkSession;

import static org.apache.spark.sql.functions.*;

public class Main {
    public static void main(String[] args) {
        var s3Endpoint = System.getenv().getOrDefault("S3_ENDPOINT", "https://localhost:9000");
        var s3AccessKey = System.getenv().getOrDefault("S3_ACCESS_KEY", "minioAccessKey");
        var s3SecretKey = System.getenv().getOrDefault("S3_SECRET_KEY", "minioSecretKey");
        var deltaTablePath = System.getenv().getOrDefault("DELTA_TABLE_PATH", "s3a://trino/delta-table");
        var skipTlsValidation = Boolean.parseBoolean(System.getenv().getOrDefault("S3_SKIP_TLS_VALIDATION", "true"));
        var sslEnabled = s3Endpoint.startsWith("https://");

        if (skipTlsValidation) {
            System.setProperty("com.amazonaws.sdk.disableCertChecking", "true");
        }

        var spark = SparkSession.builder()
                .appName("Quickstart")
                .master("local[*]")
                .config("spark.sql.extensions", "io.delta.sql.DeltaSparkSessionExtension")
                .config("spark.sql.catalog.spark_catalog", "org.apache.spark.sql.delta.catalog.DeltaCatalog")
                .config("spark.hadoop.fs.s3a.access.key", s3AccessKey)
                .config("spark.hadoop.fs.s3a.secret.key", s3SecretKey)
                .config("spark.hadoop.fs.s3a.path.style.access", "true")
                .config("spark.hadoop.fs.s3a.endpoint", s3Endpoint)
                .config("spark.hadoop.fs.s3a.connection.ssl.enabled", String.valueOf(sslEnabled))
                .config("spark.hadoop.fs.s3a.impl", "org.apache.hadoop.fs.s3a.S3AFileSystem")
                .getOrCreate();

        var data = spark.range(0, 50_000)
                .withColumn("year", lit("2026"))
                .withColumn("id_mandant", lit("7"))
                .withColumn("text", concat(lit("text"), try_divide(col("id"), lit(5000)).cast("int")))
                .select(col("year"), col("id_mandant"), col("text"));

        data.repartition(col("year"), col("id_mandant"))
                .write()
                .format("delta")
                .partitionBy("year", "id_mandant")
                .mode("append")
                .save(deltaTablePath);
    }
}
