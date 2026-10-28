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
vulns_df = nvd_df.select(explode("vulnerabilities").alias("vuln")) #one row per CVE, vuln is col name

print("cves:", vulns_df.count())

#one row per configuration, carrying the CVE id and status along
configs_df = vulns_df.select(
    col("vuln.cve.id").alias("cve_id"),
    col("vuln.cve.vulnStatus").alias("vuln_status"),
    explode("vuln.cve.configurations").alias("config"),
)
print("configurations:", configs_df.count())
configs_df.select("cve_id", "vuln_status").show(5)

#one row per node
nodes_df = configs_df.select(
    "cve_id",
    "vuln_status",
    explode("config.nodes").alias("node"),
)
print("nodes:", nodes_df.count())

#one row per cpeMatch entry (one product or platform the CVE mentions)
cpe_matches_df = nodes_df.select(
    "cve_id",
    "vuln_status",
    explode("node.cpeMatch").alias("cpe_match"),
)
print("cpe matches:", cpe_matches_df.count())
cpe_matches_df.select("cve_id", "cpe_match.criteria", "cpe_match.vulnerable").show(5, truncate=False)

spark.stop()
