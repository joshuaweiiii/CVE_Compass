from pyspark.sql import SparkSession

spark = (
    SparkSession.builder
    .appName("cve_compass") #label for job
    .master("local[*]") #use current laptop all CPU cores
    .getOrCreate() #creates spark session
)

print("spark version:", spark.version)

df = spark.createDataFrame(
    [("ASSET-001", "server"), ("ASSET-002", "laptop")],
    ["asset_id", "device_type"],
)
df.show()

spark.stop()
