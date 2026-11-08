from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    coalesce,
    col,
    explode,
    filter as filter_array,
    lit,
    split,
    transform,
    try_element_at,
    when,
)

OUTPUT_PATH = "data/processed/exposures_spark"


def version_array(column_name):
    """Turn "8.22.0" into [8, 22, 0] so versions compare as numbers, not text."""
    return transform(split(col(column_name), r"\."), lambda part: part.cast("int"))


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

#one row per configuration, carrying the CVE id and status along
configs_df = vulns_df.select(
    col("vuln.cve.id").alias("cve_id"),
    col("vuln.cve.vulnStatus").alias("vuln_status"),
    explode("vuln.cve.configurations").alias("config"),
)

#one row per node
nodes_df = configs_df.select(
    "cve_id",
    "vuln_status",
    explode("config.nodes").alias("node"),
)

#one row per cpeMatch entry (one product or platform the CVE mentions)
cpe_matches_df = nodes_df.select(
    "cve_id",
    "vuln_status",
    explode("node.cpeMatch").alias("cpe_match"),
)

#pulls only vulnerable (product not platform thats broken)
vulnerable_df = cpe_matches_df.filter(
    (col("cpe_match.vulnerable") == True) & (col("vuln_status") != "Rejected"))

#cpe_match nested column into flat table with vendor, product, and version
parts = split(col("cpe_match.criteria"), ":")
cve_products_df = vulnerable_df.select(
    "cve_id",
    parts[3].alias("vendor"),
    parts[4].alias("product"),
    parts[5].alias("cpe_version"),
    "cpe_match.versionStartIncluding", #all broken from this up
    "cpe_match.versionEndIncluding", #all broken up to this
    "cpe_match.versionEndExcluding" #first fixed one
)

#pair each CVE product with every machine that has that product installed (no version control yet)
candidates_df = cve_products_df.join(
    softwares_df,
    (cve_products_df.vendor == softwares_df.software_vendor)
    & (cve_products_df.product == softwares_df.software_name),
    "inner",
)

#version check: keep only candidates whose installed version is actually vulnerable
installed = version_array("installed_version")

#a NULL range field means no limit on that side
in_range = (
    (col("versionStartIncluding").isNull() | (installed >= version_array("versionStartIncluding")))
    & (col("versionEndIncluding").isNull() | (installed <= version_array("versionEndIncluding")))
    & (col("versionEndExcluding").isNull() | (installed < version_array("versionEndExcluding")))
)

#a specific version in the CPE string means only that exact version is vulnerable
is_exact = ~col("cpe_version").isin("*", "-")

vulnerable_matches_df = candidates_df.filter(
    (is_exact & (col("installed_version") == col("cpe_version")))
    | (~is_exact & in_range)
)

#one CVE can list overlapping ranges for the same product, so keep one row per machine + CVE + product
exposures_df = vulnerable_matches_df.dropDuplicates(["asset_id", "cve_id", "vendor", "product"])

#CVSS v3.1 score per CVE: Primary (NVD) first, else Secondary (vendor/CNA)
cvss_v31 = col("vuln.cve.metrics.cvssMetricV31")
primary = try_element_at(filter_array(cvss_v31, lambda m: m.type == "Primary"), lit(1))
secondary = try_element_at(filter_array(cvss_v31, lambda m: m.type == "Secondary"), lit(1))
chosen_metric = coalesce(primary, secondary) #use secondary, if no primary

cve_scores_df = vulns_df.select(
    col("vuln.cve.id").alias("cve_id"),
    chosen_metric.cvssData.baseScore.alias("base_score"),
    chosen_metric.cvssData.baseSeverity.alias("base_severity"),
    chosen_metric.type.alias("score_source"),
)

#add CVSS score, then asset details (hostname, exposure, criticality)
enriched_df = (
    exposures_df
    .join(cve_scores_df, "cve_id", "left")
    .join(assets_df, "asset_id", "inner")
)

#left join keeps exposures with no patch ticket; those are open
enriched_df = (
    enriched_df
    .join(patches_df, ["asset_id", "cve_id"], "left")
    .withColumn("patch_status", coalesce(col("patch_status"), lit("open")))
)

prioritized_df = enriched_df.withColumn(
    "priority",
    when(col("patch_status") == "patched", "done")
    .when(
        (col("patch_status") == "open")
        & (col("base_severity") == "CRITICAL")
        & (col("internet_exposed") == True)
        & (col("business_criticality") == "high"),
        "patch_now",
    )
    .otherwise("review"),
)

final_df = prioritized_df.select(
    "asset_id",
    "cve_id",
    col("vendor").alias("software_vendor"),
    col("product").alias("software_name"),
    "installed_version",
    "hostname",
    "device_type",
    "business_criticality",
    "internet_exposed",
    "base_score",
    "base_severity",
    "score_source",
    "patch_status",
    "priority",
)

print("exposures found:", final_df.count())
print("assets affected:", final_df.select("asset_id").distinct().count())
final_df.groupBy("priority").count().show()
final_df.groupBy("patch_status").count().show()

final_df.write.mode("overwrite").parquet(OUTPUT_PATH)
print("saved:", OUTPUT_PATH)

spark.stop()
