# Databricks notebook source
# MAGIC %md
# MAGIC # PHI/PII Metadata Discovery — Column Classification
# MAGIC
# MAGIC ## Accelerator: PHI/PII Column-Level Masking
# MAGIC ### Notebook 1 of 3 — Discover & Register PII/PHI Columns
# MAGIC
# MAGIC **Purpose**
# MAGIC
# MAGIC This notebook scans every table in every (catalog, schema) pair in the workspace
# MAGIC (excluding an explicit denylist) and heuristically identifies columns that are
# MAGIC likely to contain PII/PHI, based on keyword matching against the column name.
# MAGIC Matches are written to a central control table
# MAGIC (`workspace.silver.encrypt_columns_config`), which downstream notebooks in
# MAGIC this accelerator (`Apply_Masking`) use as the source of truth for which columns
# MAGIC to protect with Unity Catalog column masks.
# MAGIC
# MAGIC **What this notebook does**
# MAGIC 1. Defines a list of PII/PHI keyword categories (name, address, SSN, DOB, phone,
# MAGIC    email, race, Medicare/Medicaid IDs, license/NPI numbers, etc.).
# MAGIC 2. Walks every catalog/schema (minus exclusions) and every table within it.
# MAGIC 3. For each table, compares column names against the keyword list using a small
# MAGIC    set of category-specific rules (see "Matching rules" below) to reduce false
# MAGIC    positives, e.g. `flag`/`id`/`yn` suffixed columns are skipped.
# MAGIC 4. Upserts (merge) the resulting `(TableName, PIICategory, ColumnName, DataType,
# MAGIC    EncryptFlag)` tuples into the control table `encrypt_columns_config`.
# MAGIC
# MAGIC **Matching rules**
# MAGIC - General categories: any column containing the keyword (and not ending in
# MAGIC   `id`/`flag`/`yn`) is flagged.
# MAGIC - `fax`, `city`, `state`: only flagged if the column *starts or ends* with the
# MAGIC   keyword AND is of `string` type (avoids matching unrelated columns that merely
# MAGIC   contain the substring, e.g. `facility`).
# MAGIC - `mail`: only flagged if the column is of `string` type (avoids matching
# MAGIC   non-string columns that happen to contain "mail").
# MAGIC
# MAGIC **Prerequisites**
# MAGIC - Unity Catalog with `SELECT` and metadata (`SHOW TABLES`, `SHOW SCHEMAS`)
# MAGIC   privileges across the catalogs being scanned.
# MAGIC - Target control table `workspace.silver.encrypt_columns_config` must
# MAGIC   already exist with columns: `TableName`, `PIICategory`, `ColumnName`,
# MAGIC   `DataType`, `EncryptFlag`.
# MAGIC - Cluster/serverless compute with Spark + `delta` available.
# MAGIC
# MAGIC **Outputs**
# MAGIC - Rows merged into `workspace.silver.encrypt_columns_config`.
# MAGIC - A `results_df` summary (per schema: success/failure + row count/error) for
# MAGIC   auditability, displayed at the end of the run.
# MAGIC
# MAGIC **Customization**
# MAGIC - Update `pii_categories` to add/remove keyword categories for your domain.
# MAGIC - Update `exclude_catalogs` / `exclude_schema` to match your environment's
# MAGIC   non-production or infrastructure schemas.
# MAGIC - Adjust `target_table_name` if your control table lives elsewhere.
# MAGIC
# MAGIC **Note:** Keyword-based discovery is a heuristic, not a guarantee. Always review
# MAGIC the resulting control table with a data owner/steward before relying on it for
# MAGIC compliance purposes, and set `EncryptFlag = false` for any false positives.

# COMMAND ----------

import pandas as pd
from delta.tables import *

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration
# MAGIC - `pii_categories`: keyword list used to flag PII/PHI columns by name.
# MAGIC - `target_table_name`: control table that stores the resulting PII inventory
# MAGIC   and is consumed by the masking notebook downstream.

# COMMAND ----------

# Keywords used for name-based PII/PHI detection. Extend this list to cover
# additional identifiers relevant to your domain (e.g. 'passport', 'ein').
pii_categories = ['firstname','lastname','middlename',
                'street','address','zip','county','city','state',
                'dob','dod','doa',
                'ssn',
                'phone','mobile','telephone','fax',
                'mail',            
                'race',
                'medicare','medicaid',
                'license','npi'
            ]

# Control table that stores the discovered PII/PHI column inventory. This is the
# single source of truth consumed by Apply_Masking.py downstream.
target_table_name = 'workspace.silver.encrypt_columns_config'

# COMMAND ----------

# MAGIC %md
# MAGIC ## Function: `add_table_to_pii_metadata`
# MAGIC Scans a single table's columns for PII/PHI keyword matches and merges the
# MAGIC results into the control table. Useful for ad hoc runs against one table
# MAGIC without scanning an entire schema.

# COMMAND ----------

    
def add_table_to_pii_metadata(table_name):
    """
    Scan a single table's columns for PII/PHI keyword matches and upsert the
    matches into the control table `target_table_name`.

    Parameters
    ----------
    table_name : str
        Fully qualified table name, e.g. 'catalog.schema.table'.

    Returns
    -------
    pyspark.sql.DataFrame or None
        The result of the MERGE INTO statement, or None if no PII/PHI columns
        were found for this table.
    """

    df_tuple_array = []
    added_columns = []

    # Pull column name/dtype pairs for the target table.
    all_columns = spark.read.table(table_name).dtypes

    # Columns ending in these suffixes are excluded even if they contain a
    # keyword (e.g. 'is_ssn_verified_flag' should not be flagged as SSN data).
    suffixes = ('id','flag','yn')

    #table_name = schema_name+'.'+table[0]
    #table_name = table[0]


    # For every keyword category, check every column for a match, applying
    # category-specific rules to reduce false positives (see notebook header).
    for pii_category in pii_categories:
        pii_category = pii_category.lower()
        for column, dtype in all_columns:
            column = column.lower()
            dtype = dtype.lower()
            if ( pii_category in column and not (column.endswith(suffixes)) ):
                if( pii_category == 'fax' and (column.startswith('fax') or column.endswith('fax')) and dtype == 'string'):
                    # 'fax' must be a prefix/suffix and the column must be string typed
                    df_tuple_array.append((table_name,pii_category,column,dtype)) if column not in added_columns else None
                    added_columns.append(column)
                elif( pii_category == 'city' and (column.startswith('city') or column.endswith('city')) and dtype == 'string'):
                    # 'city' must be a prefix/suffix and the column must be string typed
                    df_tuple_array.append((table_name,pii_category,column,dtype)) if column not in added_columns else None
                    added_columns.append(column)
                elif( pii_category == 'state' and (column.startswith('state') or column.endswith('state')) and dtype == 'string'):
                    # 'state' must be a prefix/suffix and the column must be string typed
                    df_tuple_array.append((table_name,pii_category,column,dtype)) if column not in added_columns else None
                    added_columns.append(column)
                elif( pii_category == 'mail' and dtype == 'string'):
                    # 'mail' substring match, restricted to string columns
                    df_tuple_array.append((table_name,pii_category,column,dtype)) if column not in added_columns else None
                    added_columns.append(column)
                elif( pii_category not in ['city','state','mail','fax']):
                    # Default rule: any substring match for the remaining categories
                    df_tuple_array.append((table_name,pii_category,column,dtype)) if column not in added_columns else None
                    added_columns.append(column)

    # Only attempt the merge if we actually found candidate PII/PHI columns.
    if len(df_tuple_array) != 0:
        # EncryptFlag defaults to True for every newly discovered column; a
        # steward can flip individual rows to False after manual review.
        targetDF = spark.createDataFrame([ [x[0],x[1],x[2],x[3],True] for x in df_tuple_array], ['TableName','PIICategory','ColumnName','DataType','EncryptFlag']).distinct()


        # Upsert into the control table: update category/type/flag on existing
        # (table, column) pairs, insert new ones otherwise.
        result = spark.sql(f""" merge into {target_table_name} 
                      using targetDF on targetdf.tablename = {target_table_name}.tablename and targetdf.columnname = {target_table_name}.columnname 
                      when matched then update set {target_table_name}.piicategory = targetdf.piicategory,
                                                   {target_table_name}.datatype = targetdf.datatype,
                                                   {target_table_name}.encryptflag = targetdf.encryptflag
                      when not matched then insert (
                                                    tablename,
                                                    piicategory,
                                                    columnname,
                                                    datatype,
                                                    encryptflag
                                                )
                                                VALUES (
                                                    targetDF.tablename,
                                                    targetDF.piicategory,
                                                    targetDF.columnname,
                                                    targetDF.datatype,
                                                    targetDF.encryptflag
                                                )
                    """)
            
        return result


# COMMAND ----------

# MAGIC %md
# MAGIC ## Function: `add_schema_tables_to_pii_metadata`
# MAGIC Scans **every table** in a given `catalog.schema` for PII/PHI keyword matches
# MAGIC and merges the aggregated results into the control table in a single MERGE.
# MAGIC This is the workhorse function driven by the parallel schema-scan section
# MAGIC further down the notebook.

# COMMAND ----------

def add_schema_tables_to_pii_metadata(schema_name):
    """
    Scan every table in `schema_name` for PII/PHI keyword matches and upsert
    the aggregated matches into the control table `target_table_name`.

    Parameters
    ----------
    schema_name : str
        Fully qualified schema name, e.g. 'catalog.schema'.

    Returns
    -------
    pyspark.sql.DataFrame or None
        The result of the MERGE INTO statement, or None if no PII/PHI columns
        were found across the schema's tables.
    """

    print(f"Running for {schema_name}")
    # List all non-temporary tables in the schema.
    all_tables_list = spark.sql(f""" SHOW TABLES FROM {schema_name} """).select('tableName').filter(" isTemporary == False ").collect()
    print('show tables done')

    df_tuple_array = []
    suffixes = ('id','flag','yn')


    for table in all_tables_list:

        # Track already-matched columns per table to avoid duplicate tuples
        # when a column name matches multiple keyword categories.
        added_columns = []

        table_name = schema_name+'.'+table[0]

        
        print(f"Running for {table_name}")
        
        all_columns = spark.read.table(table_name).dtypes 

         
        

        # Same category-specific matching rules as add_table_to_pii_metadata,
        # applied per table within the schema.
        for pii_category in pii_categories:
            pii_category = pii_category.lower()
            for column, dtype in all_columns:
                column = column.lower()
                dtype = dtype.lower()
                if ( pii_category in column and not (column.endswith(suffixes)) ):
                    if( pii_category == 'fax' and (column.startswith('fax') or column.endswith('fax')) and dtype == 'string'):
                        df_tuple_array.append((table_name,pii_category,column,dtype)) if column not in added_columns else None
                        added_columns.append(column)
                    elif( pii_category == 'city' and (column.startswith('city') or column.endswith('city')) and dtype == 'string'):
                        df_tuple_array.append((table_name,pii_category,column,dtype)) if column not in added_columns else None
                        added_columns.append(column)
                    elif( pii_category == 'state' and (column.startswith('state') or column.endswith('state')) and dtype == 'string'):
                        df_tuple_array.append((table_name,pii_category,column,dtype)) if column not in added_columns else None
                        added_columns.append(column)
                    elif( pii_category == 'mail' and dtype == 'string'):
                        df_tuple_array.append((table_name,pii_category,column,dtype)) if column not in added_columns else None
                        added_columns.append(column)
                    elif( pii_category not in ['city','state','mail','fax']):
                        df_tuple_array.append((table_name,pii_category,column,dtype)) if column not in added_columns else None
                        added_columns.append(column)

    # NOTE: this check runs after the outer `for table in all_tables_list` loop
    # completes, so the MERGE below covers every table's matches found above
    # (kept as-is from the original implementation).
    if len(df_tuple_array) != 0:
        targetDF = spark.createDataFrame([ [x[0],x[1],x[2],x[3],True] for x in df_tuple_array], ['TableName','PIICategory','ColumnName','DataType','EncryptFlag']).distinct()
        
        targetDF.createOrReplaceTempView('targetDF')

        print('merging')

        # Upsert into the control table for all matches found in this schema.
        result = spark.sql(f""" merge into {target_table_name} 
                      using targetDF on targetdf.tablename = {target_table_name}.tablename and targetdf.columnname = {target_table_name}.columnname 
                      when matched then update set {target_table_name}.piicategory = targetdf.piicategory,
                                                   {target_table_name}.datatype = targetdf.datatype,
                                                   {target_table_name}.encryptflag = targetdf.encryptflag
                      when not matched then insert (
                                                    tablename,
                                                    piicategory,
                                                    columnname,
                                                    datatype,
                                                    encryptflag
                                                )
                                                VALUES (
                                                    targetDF.tablename,
                                                    targetDF.piicategory,
                                                    targetDF.columnname,
                                                    targetDF.datatype,
                                                    targetDF.encryptflag
                                                )
                    """)
            
        return result


# COMMAND ----------

# MAGIC %md
# MAGIC ## Function: `process_schema`
# MAGIC Thread-safe wrapper around `add_schema_tables_to_pii_metadata` used by the
# MAGIC `ThreadPoolExecutor` below. Captures success/failure per schema so a single
# MAGIC failing schema doesn't abort the whole run.

# COMMAND ----------

def process_schema(catalog: str, schema: str):
    """Wrapper to run the PII metadata function for one catalog.schema pair.

    Catches and records any exception so failures in a single schema don't
    stop the overall parallel scan; failures are surfaced in the results
    summary at the end of the notebook.

    Parameters
    ----------
    catalog : str
        Catalog name.
    schema : str
        Schema name within the catalog.

    Returns
    -------
    dict
        {"schema_name": str, "status": "success"|"failed", "result": Any, "error": str|None}
    """
    schema_name = f"{catalog}.{schema}"
    print(schema_name)
    try:
        result = add_schema_tables_to_pii_metadata(schema_name=schema_name)
        return {"schema_name": schema_name, "status": "success", "result": result, "error": None}
    except Exception as e:
        return {"schema_name": schema_name, "status": "failed", "result": None, "error": str(e)}

# COMMAND ----------

# Flatten 'result' into a JSON-safe string so the column has one consistent dtype
def safe_stringify(val):
    """Coerce a heterogeneous result value (Spark MERGE result, DataFrame,
    dict/list, or scalar) into a single string representation so the
    resulting pandas summary column has a consistent dtype for display."""
    if val is None:
        return None
    if isinstance(val, pd.DataFrame):
        return val.to_json(orient="records")
    if isinstance(val, (dict, list)):
        return json.dumps(val, default=str)
    return str(val)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Build the list of catalogs/schemas to scan
# MAGIC Enumerates every catalog and schema visible to the running principal, to be
# MAGIC filtered by the exclusion lists in the next cell.

# COMMAND ----------

# List to store the results
data = []

# Get all catalogs
catalogs = [row['catalog'] for row in spark.sql("SHOW CATALOGS").collect()]

# Loop through each catalog
for catalog in catalogs:
    # Quote the catalog name with backticks to handle special characters
    catalog_quoted = f"`{catalog}`"
    
    # Get all schemas in the current catalog
    schemas = [row['databaseName'] for row in spark.sql(f"SHOW SCHEMAS IN {catalog_quoted}").collect()]
    
    # Loop through each schema in the catalog
    for schema in schemas:
        # Quote the schema name with backticks to handle special characters
        schema_quoted = f"`{schema}`"
        
        # Append the catalog and schema to the data list
        data.append((catalog, schema))

# Convert the list of tuples into a DataFrame
columns = ['catalog', 'schema']
final_df = spark.createDataFrame(data, columns)

 

# COMMAND ----------

# MAGIC %md
# MAGIC ## Apply exclusion lists
# MAGIC Excludes internal, staging, test, and already-classified/restricted catalogs
# MAGIC and schemas from the scan. **Update these lists for your environment** before
# MAGIC running this accelerator elsewhere.

# COMMAND ----------

# List of catalogs to exclude (you can add more catalog names here)
exclude_catalogs = ['__databricks_internal',  'system','samples','hive_metastore']

# Filter the DataFrame to exclude specific catalogs
final_df = final_df.filter(~final_df['catalog'].isin(exclude_catalogs))
exclude_schema = ['default','information_schema','test']
final_df = final_df.filter(~final_df['schema'].isin(exclude_schema))
 

# COMMAND ----------

# Sanity check: preview the distinct catalogs that will be scanned.
display(final_df.select("catalog").distinct())

# COMMAND ----------

# MAGIC %md
# MAGIC ## Run the scan in parallel
# MAGIC Uses a `ThreadPoolExecutor` to scan multiple schemas concurrently
# MAGIC (`max_workers=5`). Each schema's success/failure and result are captured for
# MAGIC the summary table below. Increase/decrease `max_workers` based on cluster
# MAGIC size and Unity Catalog API rate limits.

# COMMAND ----------

from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd
import json

# Build the (catalog, schema) task list from the filtered DataFrame.
tasks = [(row['catalog'], row['schema']) for row in final_df.collect()]

results = []
with ThreadPoolExecutor(max_workers=5) as executor:
    # Submit one scan job per schema.
    future_to_task = {
        executor.submit(process_schema, catalog, schema): (catalog, schema)
        for catalog, schema in tasks
    }

    # Collect results as they complete (not in submission order).
    for future in as_completed(future_to_task):
        catalog, schema = future_to_task[future]
        try:
            res = future.result()
        except Exception as e:
            res = {"schema_name": f"{catalog}.{schema}", "status": "failed", "result": None, "error": str(e)}

        results.append(res)

        if res["status"] == "success":
            print(f"✅ {res['schema_name']} completed")
        else:
            print(f"❌ {res['schema_name']} failed: {res['error']}")

# Summary
success_count = sum(1 for r in results if r["status"] == "success")
print(f"\n{success_count}/{len(results)} schemas processed successfully.")

# Normalize each result's payload to a string for a clean display DataFrame.
for r in results:
    r["result"] = safe_stringify(r["result"])

results_df = pd.DataFrame(results)


# COMMAND ----------

# MAGIC %md
# MAGIC ## Run summary
# MAGIC Per-schema status (success/failed) with error detail for troubleshooting.

# COMMAND ----------

display(results_df)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Data quality check
# MAGIC Confirms the control table has no duplicate `(TableName, ColumnName)` rows
# MAGIC after the merge. Any rows returned here indicate a data quality issue that
# MAGIC should be investigated before running the masking notebook.

# COMMAND ----------

# MAGIC %sql
# MAGIC select TableName,ColumnName,count(1) from  workspace.silver.encrypt_columns_config group by TableName,ColumnName having count(1)> 1