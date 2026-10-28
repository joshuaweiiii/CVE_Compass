from pyspark.sql import SparkSession
from pyspark.sql.functions import col, explode, split

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

nvd_df = spark.read.option("multiLine", True).json("data/raw/nvd/window_page_*.json")
vulns_df = nvd_df.select(explode("vulnerabilities").alias("vuln"))

vulns_df.printSchema()
