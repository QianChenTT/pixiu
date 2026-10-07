# The log archive: the one bucket the organization trail writes to, in an account that does
# nothing else. Who can touch the logs is decided here and nowhere in the accounts being logged

resource "aws_s3_bucket" "archive" {
  provider = aws.log_archive

  # A prefix plus a generated suffix, so the real name stays out of the public repo
  bucket_prefix = "shanhai-log-archive-"

  # Terraform refuses any plan that would destroy the audit record
  lifecycle {
    prevent_destroy = true
  }
}

# A deleted or overwritten log file stays recoverable as an old version
resource "aws_s3_bucket_versioning" "archive" {
  provider = aws.log_archive
  bucket   = aws_s3_bucket.archive.id

  versioning_configuration {
    status = "Enabled"
  }
}

# S3-managed keys (the S3 default, declared so a change shows up as drift). A key of our own
# in KMS would add a second door to guard, and the function in the other account would need a
# grant on it too
resource "aws_s3_bucket_server_side_encryption_configuration" "archive" {
  provider = aws.log_archive
  bucket   = aws_s3_bucket.archive.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "archive" {
  provider = aws.log_archive
  bucket   = aws_s3_bucket.archive.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "archive_bucket" {
  provider = aws.log_archive

  # Deny any request that does not come over TLS, whoever makes it
  statement {
    sid     = "DenyRequestsWithoutTLS"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.archive.arn,
      "${aws_s3_bucket.archive.arn}/*",
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

  # The three statements below are the policy AWS documents for an organization trail, the
  # same three the first trail bucket had. The trail is in another account now, which changes
  # nothing here: the principal is the CloudTrail service and aws:SourceArn pins it to our one
  # trail. Without that condition any trail in any AWS account could be pointed at this bucket
  # (the confused deputy problem)
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.archive.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  # Lets logging continue if the trail is ever changed back to the management account only
  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/AWSLogs/${data.aws_organizations_organization.this.master_account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  # Logs from every account in the organization
  statement {
    sid       = "AWSCloudTrailOrganizationWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/AWSLogs/${data.aws_organizations_organization.this.id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  # Access from another account needs a yes on both sides. This is the bucket's yes to the
  # normalize function's role, read only and log files only. The role's own yes is in
  # functions.tf. Either one alone grants nothing
  statement {
    sid       = "NormalizeFunctionReadsLogFiles"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.archive.arn}/AWSLogs/*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.stage["normalize"].arn]
    }
  }
}

resource "aws_s3_bucket_policy" "archive" {
  provider = aws.log_archive
  bucket   = aws_s3_bucket.archive.id
  policy   = data.aws_iam_policy_document.archive_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.archive]
}

resource "aws_s3_bucket_lifecycle_configuration" "archive" {
  provider = aws.log_archive
  bucket   = aws_s3_bucket.archive.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = var.log_retention_days
    }

    # Old versions of a log file exist only if something overwrote or deleted it
    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.archive]
}

# Every new log file starts the normalize function in the security account. A bucket has one
# notification configuration, so this resource owns all of it.
#
# The filter can only match the start and the end of a key, so digest files (which also end
# in .json.gz) get through and the function skips them itself
resource "aws_s3_bucket_notification" "archive" {
  provider = aws.log_archive
  bucket   = aws_s3_bucket.archive.id

  lambda_function {
    id                  = "normalize-new-log-files"
    lambda_function_arn = aws_lambda_function.stage["normalize"].arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "AWSLogs/"
    filter_suffix       = ".json.gz"
  }

  # S3 checks that it may invoke the function at the moment this is saved
  depends_on = [aws_lambda_permission.archive_starts_normalize]
}

# The name goes into infra/management's terraform.tfvars, so the trail can be pointed here.
# Read it with: terraform output -raw archive_bucket
output "archive_bucket" {
  value     = aws_s3_bucket.archive.bucket
  sensitive = true
}
