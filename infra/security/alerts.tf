# Where a detection becomes an email. A topic is a named channel: the notify function
# publishes to it and every confirmed subscriber gets a copy. Adding a second destination
# later (a chat webhook, a ticket queue) is one more subscription, with no change to the code

# Accepted until 2027-01-14: the topic has no encryption at rest. The AWS-managed SNS key would fix it in one line,
# held for its own change since it has to be applied and the alert email tested
#trivy:ignore:AWS-0095:exp:2027-01-14
resource "aws_sns_topic" "alerts" {
  provider = aws.security
  name     = "shanhai-detections"
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
