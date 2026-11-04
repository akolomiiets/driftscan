resource "aws_s3_bucket" "separate_resources" {
  tags   = { stage = "dev" }
  bucket = "dev-s3-separate-resources"
}

resource "aws_s3_bucket_versioning" "versioning_changed_outside" {
  bucket = aws_s3_bucket.separate_resources.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "policy_changed_outside" {
  bucket = aws_s3_bucket.separate_resources.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.separate_resources.arn,
        "${aws_s3_bucket.separate_resources.arn}/*",
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}
