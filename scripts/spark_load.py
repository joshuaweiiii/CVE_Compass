from pyspark.sql import SparkSession

spark = (
    SparkSession.builder
    .appName("cve_compass") #label for job
    .master("local[*]") #use current laptop all CPU cores
    .getOrCreate() #creates spark session
)

#JSON dict to Spark DF
assets_df = spark.read.option("multiLine", True).json("data/raw/synthetic/generated/assets500.json")
softwares_df = spark.read.option("multiLine", True).json("data/raw/synthetic/generated/installed_software1396.json")
patches_df = spark.read.option("multiLine", True).json("data/raw/synthetic/generated/patches_records9773.json")

assets_df.printSchema()
softwares_df.printSchema()
patches_df.printSchema()
