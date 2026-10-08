# One trail for the whole organization: every management API call in every account and every
# region lands in one bucket. A member account's admin cannot change the trail or reach the
# bucket, so an attacker who owns pixiu cannot erase their tracks.
#
# The trail itself must live here, in the management account. Its bucket does not have to: it
# moves to the log archive account (infra/security) once that bucket exists, so this account
# stops holding data. The bucket below is the first one, kept until its last log file expires

locals {
  trail_name = "shanhai-org-trail"

  # Built by hand because the bucket policy must name the trail before the trail exists
  # (the trail refuses to start without the policy). Uses the management account's ID, as
  # AWS requires for an organization trail
  trail_arn = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:trail/${local.trail_name}"
}

resource "aws_s3_bucket" "trail" {
  # A prefix plus a generated suffix, so the real name stays out of the public repo
  bucket_prefix = "shanhai-org-trail-"

  # Terraform refuses any plan that would destroy the audit record
  lifecycle {
    prevent_destroy = true
  }
}

# A deleted or overwritten log file stays recoverable as an old version
resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id

  versioning_configuration {
    status = "Enabled"
  }
}

# S3-managed keys (the S3 default, declared so a change shows up as drift)
resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket = aws_s3_bucket.trail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "trail_bucket" {
  # Deny any request that does not come over TLS, whoever makes it
  statement {
    sid     = "DenyRequestsWithoutTLS"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.trail.arn,
      "${aws_s3_bucket.trail.arn}/*",
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

  # The three statements below are the policy AWS documents for an organization trail.
  # Each one is limited with aws:SourceArn to this one trail: without it, any CloudTrail
  # trail in any AWS account could be pointed at this bucket (the confused deputy problem)
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]

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

  # Lets logging continue if the trail is ever changed back to this account only
  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

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
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_organizations_organization.this.id}/*"]

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
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.trail]
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

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

  depends_on = [aws_s3_bucket_versioning.trail]
}

resource "aws_cloudtrail" "org" {
  name = local.trail_name

  # The log archive bucket once its name is set in terraform.tfvars, the old bucket until then.
  # CloudTrail checks the new bucket's policy before it accepts the change
  s3_bucket_name = coalesce(var.archive_bucket, aws_s3_bucket.trail.id)

  # Every account in the organization, including ones created later
  is_organization_trail = true

  # Every region, so activity in a region nobody uses is still recorded, plus the global
  # services (IAM, STS, Organizations) that log in us-east-1
  is_multi_region_trail         = true
  include_global_service_events = true

  # CloudTrail also writes signed digest files, so a changed or deleted log file can be proven
  # (aws cloudtrail validate-logs)
  enable_log_file_validation = true

  # Management events, read and write, are the default selection. No data events: they cost
  # per event and nothing needs them yet

  depends_on = [aws_s3_bucket_policy.trail]
}
