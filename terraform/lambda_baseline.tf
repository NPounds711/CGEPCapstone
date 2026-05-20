resource "aws_sqs_queue" "dlq" {
  name                      = "${local.name_prefix}-dlq-${local.suffix}"
  message_retention_seconds = 1209600
  kms_master_key_id         = aws_kms_key.cmk.id
}

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_xray" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}
