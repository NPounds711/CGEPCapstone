output "api_url" {
  value       = "${aws_apigatewayv2_stage.default.invoke_url}/intake"
  description = "POST /intake endpoint."
}

output "intake_table" {
  value       = aws_dynamodb_table.intake.name
  description = "DynamoDB table holding patient submissions."
}

output "uploads_bucket" {
  value       = aws_s3_bucket.uploads.id
  description = "S3 bucket where intake attachments land."
}

output "lambda_function_name" {
  value = aws_lambda_function.intake.function_name
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "kms_key_arn" {
  value       = aws_kms_key.cmk.arn
  description = "Customer-managed KMS key ARN."
}

output "evidence_vault_bucket" {
  value       = aws_s3_bucket.vault.id
  description = "Evidence vault bucket name."
}

output "cloudtrail_arn" {
  value       = aws_cloudtrail.main.arn
  description = "CloudTrail trail ARN."
}
