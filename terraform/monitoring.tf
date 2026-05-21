resource "aws_sns_topic" "security_alerts" {
  name              = "${local.name_prefix}-security-alerts-${local.suffix}"
  kms_master_key_id = aws_kms_key.cmk.id
}

resource "aws_cloudwatch_log_metric_filter" "root_account_usage" {
  name           = "${local.name_prefix}-root-usage-${local.suffix}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name          = "RootAccountUsage"
    namespace     = "${local.name_prefix}/Security"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_account_usage" {
  alarm_name          = "${local.name_prefix}-root-account-usage-${local.suffix}"
  alarm_description   = "AU.L2-3.3.1 / IA.L2-3.5.3: Root account activity detected"
  metric_name         = aws_cloudwatch_log_metric_filter.root_account_usage.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.root_account_usage.metric_transformation[0].namespace
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

resource "aws_cloudwatch_log_metric_filter" "iam_policy_changes" {
  name           = "${local.name_prefix}-iam-changes-${local.suffix}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = SetDefaultPolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) }"

  metric_transformation {
    name          = "IAMPolicyChanges"
    namespace     = "${local.name_prefix}/Security"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_policy_changes" {
  alarm_name          = "${local.name_prefix}-iam-policy-changes-${local.suffix}"
  alarm_description   = "AC.L2-3.1.5: IAM policy modification detected"
  metric_name         = aws_cloudwatch_log_metric_filter.iam_policy_changes.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.iam_policy_changes.metric_transformation[0].namespace
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

resource "aws_cloudwatch_log_metric_filter" "cloudtrail_config_changes" {
  name           = "${local.name_prefix}-trail-changes-${local.suffix}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"

  metric_transformation {
    name          = "CloudTrailChanges"
    namespace     = "${local.name_prefix}/Security"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_config_changes" {
  alarm_name          = "${local.name_prefix}-cloudtrail-changes-${local.suffix}"
  alarm_description   = "AU.L2-3.3.1: CloudTrail configuration change detected — audit trail integrity at risk"
  metric_name         = aws_cloudwatch_log_metric_filter.cloudtrail_config_changes.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.cloudtrail_config_changes.metric_transformation[0].namespace
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

resource "aws_cloudwatch_log_metric_filter" "kms_key_deletion" {
  name           = "${local.name_prefix}-kms-deletion-${local.suffix}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"

  metric_transformation {
    name          = "KMSKeyDeletion"
    namespace     = "${local.name_prefix}/Security"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "kms_key_deletion" {
  alarm_name          = "${local.name_prefix}-kms-key-deletion-${local.suffix}"
  alarm_description   = "SC.L2-3.13.11: KMS key disable or deletion detected — PHI encryption key at risk"
  metric_name         = aws_cloudwatch_log_metric_filter.kms_key_deletion.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.kms_key_deletion.metric_transformation[0].namespace
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
