# Where a detection becomes an email. A topic is a named channel: the notify function
# publishes to it and every confirmed subscriber gets a copy. Adding a second destination
# later (a chat webhook, a ticket queue) is one more subscription, with no change to the code

# Accepted until 2027-01-14: the AWS-managed SNS key, not a KMS key of our own. Own keys are a later learning cycle
#trivy:ignore:AWS-0136:exp:2027-01-14
resource "aws_sns_topic" "alerts" {
  provider = aws.security
  name     = "shanhai-detections"

  # Encrypted at rest with the AWS-managed SNS key. Its key policy lets principals in this
  # account use it through SNS, so the notify role needs no KMS grant of its own. The email
  # that leaves AWS is not covered by this
  kms_master_key_id = "alias/aws/sns"
}

# An email subscription stays "pending confirmation" until the link AWS mails to the address
# is clicked. That click is the one step of this folder Terraform cannot do. Until then
# nothing is delivered
resource "aws_sns_topic_subscription" "alert_email" {
  provider = aws.security

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
