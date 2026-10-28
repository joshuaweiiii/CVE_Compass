from pyspark.sql import SparkSession

spark = (
    SparkSession.builder
    .appName("cve_compass") #label for job
    .master("local[*]") #use current laptop all CPU cores
    .getOrCreate() #creates spark session
)

#JSON dict to Spark DF (multiLine: read whole file as one JSON not line by line)
assets_df = spark.read.option("multiLine", True).json("data/raw/synthetic/generated/assets500.json")
softwares_df = spark.read.option("multiLine", True).json("data/raw/synthetic/generated/installed_software1396.json")
patches_df = spark.read.option("multiLine", True).json("data/raw/synthetic/generated/patches_records9773.json")

assets_df.printSchema()
softwares_df.printSchema()
patches_df.printSchema()

assets_df.show(5)
softwares_df.show(5)
patches_df.show(5)

print(assets_df.count())
print(softwares_df.count())
print(patches_df.count())

spark.stop()
