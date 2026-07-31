# Databricks notebook source
# MAGIC %md
# MAGIC # PHI/PII Masking Functions — Setup
# MAGIC
# MAGIC ## Accelerator: PHI/PII Column-Level Masking
# MAGIC ### Notebook 0 of 3 — Create Standard Masking Functions
# MAGIC
# MAGIC **Purpose**
# MAGIC
# MAGIC This notebook creates (or replaces) the set of Unity Catalog SQL functions
# MAGIC used as **column masks** throughout this accelerator. Each function returns
# MAGIC the real column value to members of the `pii_access` group and a redacted
# MAGIC value to everyone else. These functions are referenced by name from
# MAGIC `Apply_Masking.py`'s `mask_map` and applied via
# MAGIC `ALTER TABLE ... ALTER COLUMN ... SET MASK`.
# MAGIC
# MAGIC **Run this notebook first**, before `add_pii_columns_to_metadata_table.py`
# MAGIC and `Apply_Masking.py`, since the masking notebook will fail to apply a mask
# MAGIC that doesn't exist yet.
# MAGIC
# MAGIC **Masking behavior**
# MAGIC - Authorized users (members of the Unity Catalog group `pii_access`) see the
# MAGIC   original, unmasked value.
# MAGIC - All other users see a redacted value:
# MAGIC   - Numeric/date/string/timestamp types: the **first character preserved**,
# MAGIC     remaining characters replaced with `*` (e.g. `John` → `J***`,
# MAGIC     `12345` → `1****`).
# MAGIC   - Boolean: always redacted to the literal string `'****'` (there is no
# MAGIC     meaningful "first character" of a boolean to preserve).
# MAGIC
# MAGIC **Functions created**
# MAGIC | Function | Applies to Spark type |
# MAGIC |---|---|
# MAGIC | `tc_int_mask` | `INT` |
# MAGIC | `tc_bigint_mask` | `BIGINT` |
# MAGIC | `tc_string_mask` | `STRING` |
# MAGIC | `tc_decimal_type_mask` | `DECIMAL(10,2)` |
# MAGIC | `tc_double_mask` | `DOUBLE` |
# MAGIC | `tc_float_mask` | `FLOAT` |
# MAGIC | `tc_date_mask` | `DATE` |
# MAGIC | `tc_timestamp_mask` | `TIMESTAMP` |
# MAGIC | `tc_boolean_mask` | `BOOLEAN` |
# MAGIC
# MAGIC All functions are created in the schema `workspace.silver` — update this
# MAGIC location to match your environment's convention for governance/utility
# MAGIC objects (and keep it consistent with the location referenced in
# MAGIC `Apply_Masking.py`).
# MAGIC
# MAGIC **Prerequisites**
# MAGIC - `CREATE FUNCTION` privilege on the `workspace.silver` schema.
# MAGIC - A Unity Catalog account/workspace group named `pii_access` should exist;
# MAGIC   grant it to the users/roles that are authorized to see unmasked PHI/PII.
# MAGIC
# MAGIC **Known limitation**
# MAGIC - `tc_decimal_type_mask` is hard-coded to `DECIMAL(10,2)`. If your data uses
# MAGIC   a different precision/scale, either widen this signature or add
# MAGIC   additional decimal-mask functions and extend `mask_map` in
# MAGIC   `Apply_Masking.py` accordingly.
# MAGIC - `left(...)`/`len(...)` on numeric/date/timestamp types rely on Spark's
# MAGIC   implicit cast-to-string behavior; verify this behaves as expected on your
# MAGIC   Databricks runtime version before relying on it in production.
# MAGIC
# MAGIC **Re-running this notebook**
# MAGIC All functions use `CREATE OR REPLACE FUNCTION`, so this notebook is safe to
# MAGIC re-run at any time (e.g. after modifying masking logic) without needing to
# MAGIC drop functions first.

# COMMAND ----------

# MAGIC %md
# MAGIC Standard Masking Functions

# COMMAND ----------

# MAGIC %md
# MAGIC ### `tc_int_mask` — masks `INT` columns
# MAGIC Preserves the first character, replaces the rest with `*`.

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.silver.tc_int_mask(column_value INT)
# MAGIC    RETURN IF( is_member('pii_access'), column_value, concat(left(column_value,1),repeat('*', len(column_value)-1 ) ));

# COMMAND ----------

# MAGIC %md
# MAGIC ### `tc_bigint_mask` — masks `BIGINT` columns
# MAGIC Preserves the first character, replaces the rest with `*`.

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.silver.tc_bigint_mask(column_value BIGINT)
# MAGIC    RETURN IF( is_member('pii_access'), column_value, concat(left(column_value,1),repeat('*', len(column_value)-1 ) ));

# COMMAND ----------

# MAGIC %md
# MAGIC ### `tc_string_mask` — masks `STRING` columns
# MAGIC Preserves the first character, replaces the rest with `*`. This is the
# MAGIC function applied to the majority of name/address/free-text PII columns.

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.silver.tc_string_mask(column_value STRING)
# MAGIC    RETURN IF( is_member('pii_access'), column_value, concat(left(column_value,1),repeat('*', len(column_value)-1 ) ));

# COMMAND ----------

# MAGIC %md
# MAGIC ### `tc_decimal_type_mask` — masks `DECIMAL(10,2)` columns
# MAGIC Preserves the first character, replaces the rest with `*`.
# MAGIC **Note:** fixed to precision/scale `(10,2)` — see "Known limitation" above.

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.silver.tc_decimal_type_mask(column_value DECIMAL(10,2))
# MAGIC    RETURN IF( is_member('pii_access'), column_value, concat(left(column_value,1),repeat('*', len(column_value)-1 ) ));
# MAGIC
# MAGIC

# COMMAND ----------

# MAGIC %md
# MAGIC ### `tc_double_mask` — masks `DOUBLE` columns
# MAGIC Preserves the first character, replaces the rest with `*`.

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.silver.tc_double_mask(column_value DOUBLE)
# MAGIC    RETURN IF( is_member('pii_access'), column_value, concat(left(column_value,1),repeat('*', len(column_value)-1 ) ));

# COMMAND ----------

# MAGIC %md
# MAGIC ### `tc_float_mask` — masks `FLOAT` columns
# MAGIC Preserves the first character, replaces the rest with `*`.

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.silver.tc_float_mask(column_value FLOAT)
# MAGIC    RETURN IF( is_member('pii_access'), column_value, concat(left(column_value,1),repeat('*', len(column_value)-1 ) ));

# COMMAND ----------

# MAGIC %md
# MAGIC ### `tc_date_mask` — masks `DATE` columns
# MAGIC Preserves the first character, replaces the rest with `*`. Used for
# MAGIC date-of-birth/death/admission columns (`dob`, `dod`, `doa`).

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.silver.tc_date_mask(column_value DATE)
# MAGIC    RETURN IF( is_member('pii_access'), column_value, concat(left(column_value,1),repeat('*', len(column_value)-1 ) ));

# COMMAND ----------

# MAGIC %md
# MAGIC ### `tc_timestamp_mask` — masks `TIMESTAMP` columns
# MAGIC Preserves the first character, replaces the rest with `*`.

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.silver.tc_timestamp_mask(column_value TIMESTAMP)
# MAGIC    RETURN IF( is_member('pii_access'), column_value, concat(left(column_value,1),repeat('*', len(column_value)-1 ) ));

# COMMAND ----------

# MAGIC %md
# MAGIC ### `tc_boolean_mask` — masks `BOOLEAN` columns
# MAGIC Unlike the other functions, this returns a fixed `'****'` string for
# MAGIC unauthorized users (a boolean has no meaningful "first character" to
# MAGIC preserve), and casts the true value to `STRING` for authorized users so
# MAGIC both branches share a return type.

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.silver.tc_boolean_mask(column_value BOOLEAN)
# MAGIC RETURN IF(is_member('pii_access'), CAST(column_value AS STRING), '****');

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE TABLE IF NOT EXISTS workspace.silver.encrypt_columns_config (
# MAGIC   Id           BIGINT GENERATED ALWAYS AS IDENTITY (START WITH 1 INCREMENT BY 1),
# MAGIC   TableName    STRING,
# MAGIC   PIICategory  STRING,
# MAGIC   ColumnName   STRING,
# MAGIC   DataType     STRING,
# MAGIC   EncryptFlag  BOOLEAN
# MAGIC );

# COMMAND ----------

# MAGIC %sql
# MAGIC select * from workspace.silver.encrypt_columns_config