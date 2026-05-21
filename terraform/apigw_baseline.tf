resource "aws_cloudwatch_log_group" "apigw" {
  name              = "/aws/apigateway/${local.name_prefix}-${local.suffix}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.cmk.arn
}
