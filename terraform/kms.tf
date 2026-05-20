resource "aws_kms_key" "cmk" {
  description             = "PHI data stores CMK"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "cmk" {
  name          = "alias/${local.name_prefix}-cmk-${local.suffix}"
  target_key_id = aws_kms_key.cmk.key_id
}
