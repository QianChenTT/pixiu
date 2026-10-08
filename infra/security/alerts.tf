# Where a detection becomes an email. A topic is a named channel: the notify function
# publishes to it and every confirmed subscriber gets a copy. Adding a second destination
# later (a chat webhook, a ticket queue) is one more subscription, with no change to the code

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
