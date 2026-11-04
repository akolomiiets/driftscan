resource "aws_iam_role" "assume_role_policy_drift" {
  tags = { stage = "dev" }
  name = "dev-assume-role-policy-drift"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "managed_inline_policy" {
  name = "managed-inline-policy"
  role = aws_iam_role.assume_role_policy_drift.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:ListAllMyBuckets"
      Resource = "*"
    }]
  })
}

# Second role, only for the inline-policy shape: an inline policy added outside is not reverted by apply.
resource "aws_iam_role" "extra_inline_policy_not_reverted" {
  tags = { stage = "dev" }
  name = "dev-extra-inline-policy-not-reverted"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "managed_inline_policy_of_second_role" {
  name = "managed-inline-policy"
  role = aws_iam_role.extra_inline_policy_not_reverted.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:ListAllMyBuckets"
      Resource = "*"
    }]
  })
}
