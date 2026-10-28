from pyspark.sql import SparkSession

spark = (
    SparkSession.builder
    .appName("cve_compass") #label for job
    .master("local[*]") #use current laptop all CPU cores
    .getOrCreate() #creates spark session
)

assets = spark.read.json("data/raw/synthetic/generated/assets500.json")
softwares = spark.read.json("data/raw/synthetic/generated/installed_software1396.json")
patches = spark.read.json("data/raw/synthetic/generated/patches_records9773.json")