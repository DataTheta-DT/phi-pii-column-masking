# Databricks PHI/PII Column-Level Masking Accelerator

Discover, inventory, and automatically apply Unity Catalog **column masks**
to PHI/PII columns across an entire Databricks metastore — with no manual
per-table `ALTER TABLE` work required.

## What this accelerator does

Healthcare, insurance, and other regulated data platforms typically ingest
data from dozens of source systems, each with its own naming conventions.
Manually tracking which of the thousands of resulting columns contain PHI/PII
and applying masking to each one does not scale. This accelerator automates
that end-to-end workflow:

1. **Discover** — scan every table in every catalog/schema for columns whose
   *name* matches a configurable list of PII/PHI keywords (name, address,
   SSN, DOB, phone, email, Medicare/Medicaid ID, NPI, etc.) and record them in
   a central control table.
2. **Define** — create a standard library of Unity Catalog masking SQL
   functions, one per supported data type, that reveal real values only to an
   authorized group and redact them for everyone else.
3. **Apply** — read the control table and automatically issue
   `ALTER TABLE ... SET MASK` for every flagged, not-yet-masked column,
   in parallel, safely.

The result: a self-service, repeatable process for rolling out column-level
masking across a large, evolving lakehouse, driven entirely by a control
table that data stewards can review and adjust.

## Architecture

```
                 ┌─────────────────────────────────────┐
                 │ 00_create_datamasking_function.py    │
                 │ Creates workspace.silver.tc_*_mask│
                 │ SQL functions (one per data type)    │
                 └───────────────┬───────────────────────┘
                                 │ (run once, or whenever
                                 │  masking logic changes)
                                 ▼
┌───────────────────────────────────────────┐
│ 01_add_pii_columns_to_metadata_table.py    │
│ Scans every catalog.schema.table for       │
│ columns matching PII/PHI keywords and      │
│ upserts them into the control table:       │
│   workspace.silver.encrypt_columns_config │
└───────────────────┬───────────────────────┘
                    │ (run on a schedule, or whenever
                    │  new tables/columns are added)
                    ▼
┌───────────────────────────────────────────┐
│ 02_Apply_Masking.py                        │
│ Reads the control table, skips columns     │
│ already masked, and applies                │
│ ALTER TABLE ... SET MASK to the rest       │
└───────────────────────────────────────────┘
```

## Control table schema

`workspace.silver.encrypt_columns_config`

| Column | Type | Description |
|---|---|---|
| `TableName` | string | Fully qualified `catalog.schema.table` |
| `PIICategory` | string | Keyword category that triggered the match (e.g. `ssn`, `dob`, `mail`) |
| `ColumnName` | string | Column name (lowercase) |
| `DataType` | string | Spark data type of the column at discovery time |
| `EncryptFlag` | boolean | Whether this column should be masked. Set to `false` to exempt a false-positive match from masking without deleting the row. |

This table is the single point of governance for the whole accelerator — a
data steward can review it, correct misclassifications, and toggle
`EncryptFlag` per column without touching any notebook code.

## Prerequisites

- A Databricks workspace with **Unity Catalog** enabled.
- A Unity Catalog group named `pii_access`, granted to the users/service
  principals who should be able to see unmasked values.
- The control table `workspace.silver.encrypt_columns_config` created in
  advance with the schema above (as a Delta table).
- The running principal needs, at minimum:
  - `USE CATALOG` / `USE SCHEMA` and `SELECT` on all catalogs/schemas being
    scanned (notebook 01).
  - `CREATE FUNCTION` on `workspace.silver.` (notebook 00).
  - `ALTER` on every table flagged for masking, plus `EXECUTE` on the masking
    functions (notebook 02).

> Adjust the schema/catalog names above (`workspace.silver.*`,
> `workspace.silver.*`) to match your environment's naming convention
> before deploying this accelerator — they are used consistently across all
> three notebooks.

## Setup & run order

1. **`00_create_datamasking_function.py`** — run once to create the masking
   SQL functions. Safe to re-run any time (`CREATE OR REPLACE FUNCTION`).
2. **`01_add_pii_columns_to_metadata_table.py`** — run to (re)build the PII
   inventory. Recommended on a schedule (e.g. nightly/weekly) so newly added
   tables/columns are picked up automatically. Review the exclusion lists
   (`exclude_catalogs`, `exclude_schema`) and the `pii_categories` keyword
   list before the first run in a new environment.
3. **Manual review (recommended)** — query the control table and set
   `EncryptFlag = false` on any false positives before proceeding.
4. **`02_Apply_Masking.py`** — run to apply masks to every flagged,
   unmasked column. Safe to re-run repeatedly (idempotent); it will only act
   on columns that aren't already masked.

## Masking behavior

Each masking function checks membership in the `pii_access` Unity Catalog
group:

- **Members of `pii_access`** see the original, unmasked value.
- **Everyone else** sees a redacted value:
  - Numeric, date, timestamp, and string types: first character preserved,
    remainder replaced with `*` (e.g. `Smith` → `S****`).
  - Boolean: always redacted to the literal `'****'`.

| Data type | Masking function |
|---|---|
| `INT` | `tc_int_mask` |
| `BIGINT` | `tc_bigint_mask` |
| `STRING` | `tc_string_mask` |
| `DECIMAL(10,2)` | `tc_decimal_type_mask` |
| `DOUBLE` | `tc_double_mask` |
| `FLOAT` | `tc_float_mask` |
| `DATE` | `tc_date_mask` |
| `TIMESTAMP` | `tc_timestamp_mask` |
| `BOOLEAN` | `tc_boolean_mask` |

Columns whose data type isn't in this table cause `02_Apply_Masking.py` to
raise a `ValueError` listing every affected `table.column`, so unsupported
types are surfaced rather than silently skipped.

## Known limitations & things to customize before production use

- **Heuristic discovery, not certainty.** Keyword matching on column names
  will produce false positives and false negatives. Always have a data
  steward review the control table before masks are applied broadly.
- **`tc_decimal_type_mask` is fixed to `DECIMAL(10,2)`.** Add additional
  decimal-mask function variants (and extend `mask_map` in
  `02_Apply_Masking.py`) if your data uses other precision/scale values.
- **Exclusion lists are environment-specific.** `exclude_catalogs` and
  `exclude_schema` in notebook 01 reference example catalog/schema names —
  replace them with your own non-production, staging, or already-governed
  namespaces.
- **Single masking strategy.** All functions use a "reveal first character"
  redaction. Swap in different redaction strategies (full redaction, hashing,
  tokenization, format-preserving masking, etc.) per column category if your
  compliance requirements call for it.
- **Concurrency limits.** `max_workers=5` is used throughout for parallel
  scanning/masking; tune based on your cluster size and Unity Catalog API
  rate limits.

## Repository contents

| File | Description |
|---|---|
| `00_create_datamasking_function.py` | Creates the Unity Catalog masking SQL functions. |
| `01_add_pii_columns_to_metadata_table.py` | Scans the metastore and populates the PII/PHI control table. |
| `02_Apply_Masking.py` | Applies column masks based on the control table. |

## License / disclaimer

This accelerator is provided as a reference implementation to help
bootstrap a PHI/PII masking process on Databricks + Unity Catalog. It is
**not** a certified compliance tool — validate the discovery keyword list,
review the control table output, and confirm masking behavior meets your
organization's regulatory obligations (e.g. HIPAA, HITECH) before relying on
it in production.
