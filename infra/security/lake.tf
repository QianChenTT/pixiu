# Asking questions of the store with SQL. Nothing here holds data: a Glue table is only a
# description (where the files are, how to read them, which columns they have) and Athena
# reads the files in S3 each time a query runs. Billing is by data read, not by the hour

locals {
  # One description of the columns for the code and for both tables. tests/test_event_schema.py
  # checks what the normalizer really writes against this same file
  schema = jsondecode(file("${local.repo_root}/pipeline/event_schema.json"))

  lake_tables = {
    events = {
      description = "Normalized events (OCSF API Activity), one row per API call"
      columns     = local.schema.event
    }
    # A match is the event itself plus which rule matched and when
    matches = {
      description = "Events a detection matched"
      columns     = concat(local.schema.match, local.schema.event)
    }
  }
}

resource "aws_glue_catalog_database" "shanhai" {
  provider = aws.security

  name        = "shanhai"
  description = "The detection store: normalized events and the matches found in them"
}

resource "aws_glue_catalog_table" "lake" {
  for_each = local.lake_tables
  provider = aws.security

  name          = each.key
  database_name = aws_glue_catalog_database.shanhai.name
  description   = each.value.description
  table_type    = "EXTERNAL_TABLE"

  # Files sit in one folder per day (dt=2026-10-07). Partition projection lets Athena work out
  # which folders exist from the rule below, so no job has to register each new day
  parameters = {
    EXTERNAL                      = "TRUE"
    classification                = "json"
    "projection.enabled"          = "true"
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy-MM-dd"
    "projection.dt.range"         = "2026-10-01,NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "storage.location.template"   = "s3://${aws_s3_bucket.store.bucket}/${each.key}/dt=$${dt}"
  }

  partition_keys {
    name    = "dt"
    type    = "string"
    comment = "The day (UTC) CloudTrail delivered the log file. A query with a dt condition reads only those days"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.store.bucket}/${each.key}/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    # One JSON object per line, read with the Hive JSON reader. The better known OpenX one is
    # avoided: AWS's own docs warn that its results can come back inconsistent
    ser_de_info {
      name                  = "json"
      serialization_library = "org.apache.hive.hcatalog.data.JsonSerDe"
    }

    dynamic "columns" {
      for_each = each.value.columns

      content {
        name    = columns.value.name
        type    = columns.value.type
        comment = try(columns.value.comment, null)
      }
    }
  }
}

# A workgroup is a set of query settings people share. This one fixes where results go and
# caps how much one query may read
resource "aws_athena_workgroup" "shanhai" {
  provider = aws.security

  name        = "shanhai"
  description = "Queries over the detection store"

  configuration {
    # A user cannot override the settings below from the console or the CLI
    enforce_workgroup_configuration = true

    bytes_scanned_cutoff_per_query = var.query_scan_limit_bytes

    result_configuration {
      output_location = "s3://${aws_s3_bucket.store.bucket}/athena-results/"

      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}

# Saved queries, so the first look at the data is a click and not a blank editor.
# The condition on dt keeps each one to the last two days of files
resource "aws_athena_named_query" "latest_events" {
  provider = aws.security

  name        = "Latest events"
  description = "The 50 newest normalized events. Use it to see that logs are flowing"
  workgroup   = aws_athena_workgroup.shanhai.id
  database    = aws_glue_catalog_database.shanhai.name

  query = <<-SQL
    SELECT time_dt,
           cloud.account.uid AS account,
           cloud.region      AS region,
           api.service.name  AS service,
           api.operation     AS operation,
           status,
           actor.user.uid    AS actor
    FROM shanhai.events
    WHERE dt >= date_format(current_date - interval '1' day, '%Y-%m-%d')
    ORDER BY "time" DESC
    LIMIT 50
  SQL
}

resource "aws_athena_named_query" "stop_logging" {
  provider = aws.security

  name        = "StopLogging calls"
  description = "Every attempt to stop a CloudTrail trail in the last two days, allowed or refused"
  workgroup   = aws_athena_workgroup.shanhai.id
  database    = aws_glue_catalog_database.shanhai.name

  query = <<-SQL
    SELECT time_dt,
           cloud.account.uid   AS account,
           status,
           api.response.error  AS error,
           json_extract_scalar(api.request.data, '$.name') AS trail,
           actor.user.uid      AS actor,
           src_endpoint.ip     AS source_ip
    FROM shanhai.events
    WHERE dt >= date_format(current_date - interval '1' day, '%Y-%m-%d')
      AND api.service.name = 'cloudtrail.amazonaws.com'
      AND api.operation = 'StopLogging'
    ORDER BY "time" DESC
  SQL
}

resource "aws_athena_named_query" "latest_matches" {
  provider = aws.security

  name        = "Latest matches"
  description = "What the detections found in the last two days"
  workgroup   = aws_athena_workgroup.shanhai.id
  database    = aws_glue_catalog_database.shanhai.name

  query = <<-SQL
    SELECT matched_at,
           rule_id,
           time_dt,
           cloud.account.uid AS account,
           api.operation     AS operation,
           status,
           actor.user.uid    AS actor
    FROM shanhai.matches
    WHERE dt >= date_format(current_date - interval '1' day, '%Y-%m-%d')
    ORDER BY matched_at DESC
  SQL
}
