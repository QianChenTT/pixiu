# Terraform's own state lives in this bucket. State maps the whole account and can hold 
# generated secrets in plain text, so the bucket is treated like a secret

resource "aws_s3_bucket" "state" {
  # A prefix plus a suffix generated at creation: the real name stays out of the public repo
  # and lives only in the local backend file
  bucket_prefix = "pixiu-tfstate-"

  # Terraform refuses any plan that would destroy this bucket: losing it loses every state version
  lifecycle {
    prevent_destroy = true
  }
}

# Every write keeps the previous state as an old version, so a broken or deleted state can be rolled back
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

# S3-managed keys (the S3 default, declared so a change shows up as drift)
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# No ACL or bucket policy can ever make this bucket or its objects public
resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Deny any request that does not come over TLS, whoever makes it
data "aws_iam_policy_document" "state_tls_only" {
  statement {
    sid     = "DenyRequestsWithoutTLS"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.state.arn,
      "${aws_s3_bucket.state.arn}/*",
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

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state_tls_only.json

  depends_on = [aws_s3_bucket_public_access_block.state]
}

# Old state versions still hold whatever secrets the state had, so they are trimmed:
# the 5 newest old versions are always kept, older ones go 30 days after they were replaced
resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "trim-old-state-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      newer_noncurrent_versions = 5
      noncurrent_days           = 30
    }

    # The lock file is created and deleted on every run, which leaves delete markers behind
    expiration {
      expired_object_delete_marker = true
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.state]
}

# Needed once, to write the local backend file. Read it with: terraform output -raw state_bucket
output "state_bucket" {
  value     = aws_s3_bucket.state.bucket
  sensitive = true
}
