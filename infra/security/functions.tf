# The three stages of the pipeline, as functions in the security account. All three run the
# same package (the pipeline/ and detections/ folders of this repo) and differ in which
# handler they call, what starts them and what their role may touch

locals {
  stage_names = toset(["normalize", "detect", "notify"])

  stages = {
    normalize = {
      description = "A new CloudTrail log file in the log archive becomes a file of normalized events"
      environment = { STORE_BUCKET = aws_s3_bucket.store.id }
    }
    detect = {
      description = "Every detection runs over a new file of normalized events and the matches are written out"
      environment = {}
    }
    notify = {
      description = "A new file of matches becomes one email"
      environment = { ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn }
    }
  }

  # Only the Python files: no caches, no tests, no schema file
  package_files = sort(concat(
    tolist(fileset(local.repo_root, "pipeline/*.py")),
    tolist(fileset(local.repo_root, "detections/*.py")),
  ))
}

# The zip is rebuilt whenever a file in it changes, and its hash is what tells Terraform to
# update the functions. So a new or edited detection ships with the next apply
data "archive_file" "pipeline" {
  type        = "zip"
  output_path = "${path.module}/.build/pipeline.zip"

  dynamic "source" {
    for_each = local.package_files

    content {
      filename = source.value
      # Windows checkouts have CRLF line endings. Normalized so the zip, and with it the
      # hash, is the same whichever machine builds it
      content = replace(file("${local.repo_root}/${source.value}"), "\r\n", "\n")
    }
  }
}

# Each function's log group is made here, before the function, so its retention is ours to
# set. Left to itself Lambda creates one that keeps logs forever
resource "aws_cloudwatch_log_group" "stage" {
  for_each = local.stage_names
  provider = aws.security

  name              = "/aws/lambda/shanhai-${each.key}"
  retention_in_days = 30
}

# Who may wear the role: the Lambda service, to run a function
data "aws_iam_policy_document" "lambda_trust" {
  provider = aws.security

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# One role per stage, so each stage can reach only what its own step needs
resource "aws_iam_role" "stage" {
  for_each = local.stage_names
  provider = aws.security

  name               = "shanhai-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

# What each role may do. Read these three side by side: every stage reads from one place and
# writes to the next, and none can write where it reads
data "aws_iam_policy_document" "normalize" {
  provider = aws.security

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.stage["normalize"].arn}:*"]
  }

  # The role's half of the two-sided yes. The bucket's half is in archive.tf
  statement {
    sid       = "ReadRawLogFiles"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.archive.arn}/AWSLogs/*"]
  }

  statement {
    sid       = "WriteNormalizedEvents"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.store.arn}/events/*"]
  }
}

data "aws_iam_policy_document" "detect" {
  provider = aws.security

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.stage["detect"].arn}:*"]
  }

  statement {
    sid       = "ReadNormalizedEvents"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.store.arn}/events/*"]
  }

  statement {
    sid       = "WriteMatches"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.store.arn}/matches/*"]
  }
}

data "aws_iam_policy_document" "notify" {
  provider = aws.security

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.stage["notify"].arn}:*"]
  }

  statement {
    sid       = "ReadMatches"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.store.arn}/matches/*"]
  }

  statement {
    sid       = "SendTheEmail"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

locals {
  stage_policies = {
    normalize = data.aws_iam_policy_document.normalize.json
    detect    = data.aws_iam_policy_document.detect.json
    notify    = data.aws_iam_policy_document.notify.json
  }
}

resource "aws_iam_role_policy" "stage" {
  for_each = local.stage_names
  provider = aws.security

  name   = "shanhai-${each.key}"
  role   = aws_iam_role.stage[each.key].id
  policy = local.stage_policies[each.key]
}

resource "aws_lambda_function" "stage" {
  for_each = local.stages
  provider = aws.security

  function_name = "shanhai-${each.key}"
  description   = each.value.description
  role          = aws_iam_role.stage[each.key].arn

  # 3.13 matches the repo's container. arm64 costs less and plain Python runs the same on it
  runtime       = "python3.13"
  architectures = ["arm64"]
  handler       = "pipeline.${each.key}.handler"

  filename         = data.archive_file.pipeline.output_path
  source_code_hash = data.archive_file.pipeline.output_base64sha256

  # A log file is a few hundred kilobytes at most. A run that takes a minute is stuck
  memory_size = 256
  timeout     = 60

  logging_config {
    log_format = "JSON"
    log_group  = aws_cloudwatch_log_group.stage[each.key].name
  }

  # Left out for a stage that has no variables to set
  dynamic "environment" {
    for_each = [for variables in [each.value.environment] : variables if length(variables) > 0]

    content {
      variables = environment.value
    }
  }

  # The role must be able to write its logs before the first run
  depends_on = [aws_iam_role_policy.stage]
}

# Who may start each function: S3, and only for the one bucket named, and only while that
# bucket still belongs to the account named. A bucket name can be claimed by anyone once its
# owner deletes it, which is what source_account guards against

resource "aws_lambda_permission" "archive_starts_normalize" {
  provider = aws.security

  statement_id   = "LogArchiveBucketStartsNormalize"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.stage["normalize"].function_name
  principal      = "s3.amazonaws.com"
  source_arn     = aws_s3_bucket.archive.arn
  source_account = var.account_ids.log_archive
}

resource "aws_lambda_permission" "store_starts_detect" {
  provider = aws.security

  statement_id   = "StoreBucketStartsDetect"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.stage["detect"].function_name
  principal      = "s3.amazonaws.com"
  source_arn     = aws_s3_bucket.store.arn
  source_account = var.account_ids.security
}

resource "aws_lambda_permission" "store_starts_notify" {
  provider = aws.security

  statement_id   = "StoreBucketStartsNotify"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.stage["notify"].function_name
  principal      = "s3.amazonaws.com"
  source_arn     = aws_s3_bucket.store.arn
  source_account = var.account_ids.security
}
