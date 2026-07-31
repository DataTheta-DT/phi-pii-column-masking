# Databricks notebook source
# MAGIC %md
# MAGIC # PHI/PII Column Masking — Apply Unity Catalog Masks
# MAGIC
# MAGIC ## Accelerator: PHI/PII Column-Level Masking
# MAGIC ### Notebook 2 of 3 — Apply Column Masks Based on the PII Inventory
# MAGIC
# MAGIC **Purpose**
# MAGIC
# MAGIC This notebook consumes the PII/PHI inventory produced by
# MAGIC `01_add_pii_columns_to_metadata_table.py` (the control table
# MAGIC `workspace.silver.encrypt_columns_config`) and applies Unity Catalog
# MAGIC column masking functions (created by
# MAGIC `create_datamasking_function.py`) to every flagged column that isn't
# MAGIC already masked.
# MAGIC
# MAGIC **What this notebook does**
# MAGIC 1. Reads the distinct list of tables with `EncryptFlag = true` from the
# MAGIC    control table.
# MAGIC 2. For each table, runs `SHOW CREATE TABLE` to discover columns that
# MAGIC    **already** have a `MASK` applied (idempotency check — avoids re-applying
# MAGIC    or erroring on already-masked columns). Tables that fail (e.g. dropped,
# MAGIC    permission issue, view instead of table) are removed from the control
# MAGIC    table and skipped.
# MAGIC 3. Anti-joins the control table against the already-masked columns to get
# MAGIC    the set of columns that still need a mask applied.
# MAGIC 4. Maps each column's data type to the corresponding masking SQL function
# MAGIC    (see `create_datamasking_function.py`) and applies it in parallel via
# MAGIC    `ALTER TABLE ... ALTER COLUMN ... SET MASK ...`, with a per-table lock to
# MAGIC    guarantee that concurrent `ALTER TABLE` statements never target the same
# MAGIC    table at once (Delta/UC do not allow concurrent DDL on one table).
# MAGIC
# MAGIC **Prerequisites**
# MAGIC - `01_add_pii_columns_to_metadata_table.py` has been run and the control
# MAGIC   table `workspace.silver.encrypt_columns_config` is populated.
# MAGIC - `create_datamasking_function.py` has been run so all
# MAGIC   `dev_edw_silver.test.tc_*_mask` SQL functions exist.
# MAGIC - The running principal has `ALTER` privileges on every table with
# MAGIC   `EncryptFlag = true`, and `EXECUTE` on the masking functions.
# MAGIC - A Unity Catalog group named `pii_access` exists and is granted to users
# MAGIC   who should see unmasked values (see masking function definitions).
# MAGIC
# MAGIC **Outputs**
# MAGIC - `ALTER TABLE ... SET MASK` applied to every unmasked, flagged column whose
# MAGIC   data type is supported.
# MAGIC - Console log of per-column success/failure.
# MAGIC - Rows removed from the control table for tables that could not be
# MAGIC   introspected (e.g. table no longer exists).
# MAGIC
# MAGIC **Supported data types**
# MAGIC `int`, `bigint`, `decimal(p,s)`, `double`, `float`, `date`, `timestamp`,
# MAGIC `string`, `boolean`. A column with an unsupported data type raises a
# MAGIC `ValueError` at the end of the run listing every affected `table.column` —
# MAGIC review these and either add a masking function for the type or set
# MAGIC `EncryptFlag = false` for that column in the control table.
# MAGIC
# MAGIC **Idempotency & re-runs**
# MAGIC This notebook is safe to re-run: columns that already have a mask applied
# MAGIC (detected via `SHOW CREATE TABLE`) are excluded from the anti-join and will
# MAGIC not be re-altered.
# MAGIC
# MAGIC **Concurrency model**
# MAGIC - Different tables are masked concurrently (`ThreadPoolExecutor`,
# MAGIC   `max_workers=5`).
# MAGIC - Multiple columns on the *same* table are serialized via a per-table
# MAGIC   `threading.Lock` to avoid concurrent DDL conflicts on one table.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1 — Load the tables to process
# MAGIC Pulls the distinct set of tables flagged for encryption/masking from the
# MAGIC control table populated by the discovery notebook.

# COMMAND ----------

config_tables = spark.sql(""" SELECT distinct TableName    FROM workspace.silver.encrypt_columns_config where EncryptFlag = true   """).collect()
display(config_tables)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2 — Detect columns that are already masked
# MAGIC For each table in the control table, parse `SHOW CREATE TABLE` DDL to find
# MAGIC any column already carrying a `MASK` clause, so the apply step later doesn't
# MAGIC attempt to redundantly (or incorrectly) re-mask it. Tables that error out on
# MAGIC introspection (e.g. no longer exist, insufficient privilege, or are a view)
# MAGIC are removed from the control table and recorded as skipped.

# COMMAND ----------

from pyspark.sql import Row
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

results = []
results_lock = threading.Lock()  # protects `results` during concurrent writes
skipped = []

def process_table(row):
    """
    Inspect one table's DDL to find columns that already have a Unity Catalog
    MASK applied.

    On failure (table missing/inaccessible/not introspectable), the table's
    rows are removed from the control table so subsequent runs don't keep
    retrying a dead reference.

    Parameters
    ----------
    row : pyspark.sql.Row
        A row with a `TableName` field, from `config_tables`.

    Returns
    -------
    dict
        {"tableName": str, "status": "success"|"skipped"|"failed",
         "masked_cols": list[Row], "error": str|None}
    """
    tableName = row['TableName']
    local_masked = []

    try:
        # Execute SHOW CREATE TABLE command
        ddl = spark.sql(f"SHOW CREATE TABLE {tableName}").collect()[0][0]

        # Scan the DDL text line by line for columns carrying a MASK clause.
        masked_cols = []
        for line in ddl.split("\n"):
            if " MASK " in line or "MASK" in line:
                col = line.strip().split()[0].replace("`", "")
                masked_cols.append(col)

        for col in masked_cols:
            local_masked.append(Row(TableName=tableName, ColumnName=col))

        return {"tableName": tableName, "status": "success", "masked_cols": local_masked, "error": None}

    except Exception as e:
        # SHOW CREATE TABLE failed (e.g. table dropped, no permission, or it's
        # a view). Clean up the control table so this table is not retried
        # indefinitely by future runs.
        try:
            spark.sql(f"DELETE FROM workspace.silver.encrypt_columns_config WHERE TableName='{tableName}'")
        except Exception as del_err:
            return {"tableName": tableName, "status": "failed", "masked_cols": [], "error": f"SHOW CREATE failed: {e} | DELETE failed: {del_err}"}

        return {"tableName": tableName, "status": "skipped", "masked_cols": [], "error": str(e)}


# Introspect tables concurrently for speed; each table's DDL check is
# independent so this is embarrassingly parallel.
with ThreadPoolExecutor(max_workers=5) as executor:
    future_to_table = {executor.submit(process_table, row): row['TableName'] for row in config_tables}

    for future in as_completed(future_to_table):
        tableName = future_to_table[future]
        try:
            res = future.result()
        except Exception as e:
            res = {"tableName": tableName, "status": "failed", "masked_cols": [], "error": str(e)}

        if res["status"] == "success":
            with results_lock:
                results.extend(res["masked_cols"])
            print(f"✅ {tableName}: found {len(res['masked_cols'])} masked column(s)")
        elif res["status"] == "skipped":
            skipped.append(tableName)
            print(f"⚠️ Skipping {tableName}: {res['error']}")
        else:
            skipped.append(tableName)
            print(f"❌ {tableName} failed entirely: {res['error']}")

print(f"\n{len(results)} masked columns found across tables. {len(skipped)} tables skipped/failed.")

# Convert to DataFrame and drop duplicates
if results:
    masked_df = spark.createDataFrame(results)
    masked_df = masked_df.dropDuplicates()
    display(masked_df)
else:
    print("No masked columns found.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3 — Reload the current control table state
# MAGIC Re-reads `encrypt_columns_config` after Step 2's cleanup (deleted dead
# MAGIC tables), scoped to `EncryptFlag = true`.

# COMMAND ----------

config_df = spark.sql(""" SELECT *  FROM workspace.silver.encrypt_columns_config    WHERE  EncryptFlag = true  """) 
display(config_df)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4 — Determine which columns still need masking
# MAGIC Left-anti-joins the flagged control-table columns against the columns
# MAGIC already carrying a mask (from Step 2), so only genuinely unmasked columns
# MAGIC proceed to the apply step. This is what makes the notebook idempotent.

# COMMAND ----------

from pyspark.sql.functions import col, lower

joined_df = config_df.alias("c").join(
    masked_df.alias("m"),
    (lower(col("c.TableName")) == lower(col("m.TableName"))) &
    (lower(col("c.ColumnName")) == lower(col("m.ColumnName"))),
    "left"
)
# Keep only rows with no matching entry in masked_df, i.e. columns that are
# NOT yet masked and therefore need a MASK applied in Step 6.
joined_df_filtered = joined_df.filter(~col("m.TableName").isNotNull())

display(joined_df_filtered)



# COMMAND ----------

# MAGIC %md
# MAGIC ## Helper — per-table lock accessor
# MAGIC Returns (creating if necessary) the `threading.Lock` for a given table name,
# MAGIC guarded by `locks_guard` so lock creation itself is thread-safe. This
# MAGIC guarantees `ALTER TABLE` statements against the same table never run
# MAGIC concurrently, while different tables can still be altered in parallel.

# COMMAND ----------


def get_table_lock(table_name):
    """Return the per-table threading.Lock for `table_name`, creating it on
    first access. Guarded by `locks_guard` to make lock creation itself
    thread-safe under concurrent access from the executor pool."""
    with locks_guard:
        return table_locks[table_name]

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5 — Define the per-column masking routine
# MAGIC For a single (table, column, data type) row, resolves the appropriate
# MAGIC masking SQL function and applies it via `ALTER TABLE ... SET MASK`,
# MAGIC serialized per table using the lock helper above.

# COMMAND ----------

def process_row(row):
    """
    Apply the appropriate Unity Catalog column mask to a single column.

    Resolves the column's data type to a masking function name (see
    `mask_map`), then executes `ALTER TABLE ... ALTER COLUMN ... SET MASK`
    while holding the table's lock so no two threads issue concurrent DDL
    against the same table.

    Parameters
    ----------
    row : pyspark.sql.Row
        A row from `joined_df_filtered` with TableName, ColumnName, DataType.

    Returns
    -------
    dict
        {"table": str, "column": str, "status": "success"|"failed", "error": str|None}
    """
    table_name = row["TableName"]
    column_name = row["ColumnName"]
    data_type = row["DataType"].lower()

    # handle decimal separately if it has precision/scale like decimal(10,2)
    if data_type.startswith("decimal"):
        mask_function = mask_map["decimal"]
    else:
        mask_function = mask_map.get(data_type)

    if not mask_function:
        # No masking function registered for this data type — surfaced as a
        # failure and re-raised as a ValueError at the end of the run so it
        # isn't silently missed.
        return {"table": table_name, "column": column_name, "status": "failed",
                "error": f"Unsupported data type: {data_type}"}

    sql = f"""
        ALTER TABLE {table_name}
        ALTER COLUMN {column_name}
        SET MASK workspace.silver.{mask_function}
    """

    lock = get_table_lock(table_name)
    try:
        with lock:  # serialize ALTERs on the same table; different tables run in parallel
            spark.sql(sql)
        return {"table": table_name, "column": column_name, "status": "success", "error": None}
    except Exception as e:
        return {"table": table_name, "column": column_name, "status": "failed", "error": str(e)}


# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 6 — Apply masks in parallel
# MAGIC - `mask_map` binds each supported Spark data type to its masking SQL
# MAGIC   function (created in `create_datamasking_function.py`).
# MAGIC - Columns are processed concurrently (`max_workers=5`) across tables, with
# MAGIC   per-table locking to keep DDL safe (see Step 5 / `get_table_lock`).
# MAGIC - Any column with an unsupported data type raises a `ValueError` at the end
# MAGIC   so unsupported types are never silently skipped.

# COMMAND ----------

from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from collections import defaultdict

# Map Spark data types to their corresponding masking SQL function, defined
# in create_datamasking_function.py. Extend this map (and add a matching
# tc_<type>_mask function) to support additional data types.
mask_map = {
    "int": "tc_int_mask",
    "bigint": "tc_bigint_mask",
    "decimal": "tc_decimal_type_mask",
    "double": "tc_double_mask",
    "float": "tc_float_mask",
    "date": "tc_date_mask",
    "timestamp": "tc_timestamp_mask",
    "string": "tc_string_mask",
    "boolean": "tc_boolean_mask"
}

rows = joined_df_filtered.collect()

# One lock per table so concurrent ALTERs never hit the same table at once
table_locks = defaultdict(threading.Lock)
locks_guard = threading.Lock()  # protects creation of new locks in table_locks

results = []
with ThreadPoolExecutor(max_workers=5) as executor:
    future_to_row = {executor.submit(process_row, row): row for row in rows}

    for future in as_completed(future_to_row):
        row = future_to_row[future]
        try:
            res = future.result()
        except Exception as e:
            res = {"table": row["TableName"], "column": row["ColumnName"], "status": "failed", "error": str(e)}

        results.append(res)

        if res["status"] == "success":
            print(f"✅ {res['table']}.{res['column']} masked")
        else:
            print(f"❌ {res['table']}.{res['column']} failed: {res['error']}")

success_count = sum(1 for r in results if r["status"] == "success")
print(f"\n{success_count}/{len(results)} columns masked successfully.")

# Optional: raise if anything failed due to unsupported types, mirroring original behavior
# Surfacing unsupported types loudly (rather than silently skipping) ensures
# new/unexpected data types don't slip through unmasked.
failed_unsupported = [r for r in results if r["status"] == "failed" and "Unsupported data type" in (r["error"] or "")]
if failed_unsupported:
    types_msg = "; ".join(f"{r['table']}.{r['column']}" for r in failed_unsupported)
    raise ValueError(f"Unsupported data type(s) encountered for: {types_msg}")