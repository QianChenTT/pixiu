# The store: one bucket in the security account for everything the pipeline produces.
#
#   events/          normalized events, one file per raw log file    (written by normalize)
#   matches/         one file per events file that matched a rule    (written by detect)
#   athena-results/  the result files of Athena queries              (written by Athena)
#
# Two of the three stages are started by a new file in this same bucket, which is the classic
# way to build a function that triggers itself forever. Three things stand in the way:
# each trigger only fires for its own folder (below), each function's role can only write to
# the folder after its own (functions.tf), and the code ignores a key from the wrong folder

resource "aws_s3_bucket" "store" {
  provider = aws.security

  # A prefix plus a generated suffix, so the real name stays out of the public repo
  bucket_prefix = "shanhai-detection-store-"
}

# An overwritten or deleted file stays recoverable as an old version
resource "aws_s3_bucket_versioning" "store" {
  provider = aws.security
  bucket   = aws_s3_bucket.store.id

  versioning_configuration {
    status = "Enabled"
  }
}

# S3-managed keys (the S3 default, declared so a change shows up as drift)
resource "aws_s3_bucket_server_side_encryption_configuration" "store" {
  provider = aws.security
  bucket   = aws_s3_bucket.store.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "store" {
  provider = aws.security
  bucket   = aws_s3_bucket.store.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Deny any request that does not come over TLS, whoever makes it. Nothing else is granted
# here: everyone who uses this bucket is in this account and gets access from their own role
data "aws_iam_policy_document" "store_tls_only" {
  provider = aws.security

  statement {
    sid     = "DenyRequestsWithoutTLS"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.store.arn,
      "${aws_s3_bucket.store.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "store" {
  provider = aws.security
  bucket   = aws_s3_bucket.store.id
  policy   = data.aws_iam_policy_document.store_tls_only.json

  depends_on = [aws_s3_bucket_public_access_block.store]
}

resource "aws_s3_bucket_lifecycle_configuration" "store" {
  provider = aws.security
  bucket   = aws_s3_bucket.store.id

  # Normalized events can be rebuilt from the raw logs, so they live exactly as long
  rule {
    id     = "expire-old-events"
    status = "Enabled"

    filter {
      prefix = "events/"
    }

    expiration {
      days = var.log_retention_days
    }
  }

  # A query result is a throwaway copy
  rule {
    id     = "expire-query-results"
    status = "Enabled"

    filter {
      prefix = "athena-results/"
    }

    expiration {
      days = 7
    }
  }

  # No rule expires matches/: what the detections found is kept

  rule {
    id     = "trim-old-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.store]
}

# A bucket has one notification configuration, so both triggers live in this one resource
resource "aws_s3_bucket_notification" "store" {
  provider = aws.security
  bucket   = aws_s3_bucket.store.id

  lambda_function {
    id                  = "detect-on-new-events"
    lambda_function_arn = aws_lambda_function.stage["detect"].arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "events/"
  }

  lambda_function {
    id                  = "notify-on-new-matches"
    lambda_function_arn = aws_lambda_function.stage["notify"].arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "matches/"
  }

  # S3 checks that it may invoke each function at the moment this is saved
  depends_on = [
    aws_lambda_permission.store_starts_detect,
    aws_lambda_permission.store_starts_notify,
  ]
}

output "store_bucket" {
  value     = aws_s3_bucket.store.bucket
  sensitive = true
}
