#!/usr/bin/env bash
# Makes changes outside Terraform, one block per drift shape. Needs moto from `make up`.
set -euo pipefail

export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
EP=http://localhost:5555
aws_() { aws --endpoint-url="$EP" --no-cli-pager "$@"; }
queue_url() { aws_ sqs get-queue-url --queue-name "$1" --query QueueUrl --output text; }
sg_id() { aws_ ec2 describe-security-groups --filters "Name=group-name,Values=$1" --query 'SecurityGroups[0].GroupId' --output text; }

# 1. Simple scalar attribute (expect Drift on visibility_timeout_seconds)
aws_ sqs set-queue-attributes --queue-url "$(queue_url dev-scalar-attribute-drift)" --attributes VisibilityTimeout=60
# 1. Simple scalar attribute, SSM description (expect Drift on description)
aws_ ssm put-parameter --name /dev/scalar-description-drift --type String --value hello \
  --description "edited in the console" --overwrite >/dev/null

# 2. Map attribute: change one tag, add one, remove one (expect Drift on tags.* / tags_all.*)
aws_ sqs tag-queue --queue-url "$(queue_url dev-map-tags-drift)" --tags changed=after,added_outside=yes
aws_ sqs untag-queue --queue-url "$(queue_url dev-map-tags-drift)" --tag-keys to_remove

# 3. Set of nested blocks: replace the ssh rule (expect Drift on ingress[N].* positional set paths)
sg=$(sg_id dev-inline-ingress-set-drift)
aws_ ec2 revoke-security-group-ingress --group-id "$sg" --protocol tcp --port 22 --cidr 10.1.0.0/16
aws_ ec2 authorize-security-group-ingress --group-id "$sg" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null

# 3b. Set of nested blocks, DB parameter group: change one parameter value and one apply method
# (expect Drift on parameter[N].value / parameter[N].apply_method with shifted positional indices)
aws_ rds modify-db-parameter-group --db-parameter-group-name dev-parameter-set-drift --parameters \
  "ParameterName=max_connections,ParameterValue=500,ApplyMethod=pending-reboot" \
  "ParameterName=log_min_duration_statement,ParameterValue=500,ApplyMethod=pending-reboot" >/dev/null

# 4. Rules managed by separate resources: add a rule Terraform does not know (expect acknowledged not_reverted)
sg=$(sg_id dev-separate-rules-not-reverted)
aws_ ec2 authorize-security-group-ingress --group-id "$sg" --protocol tcp --port 8080 --cidr 0.0.0.0/0 >/dev/null

# 5a. IAM role with separately managed inline policy: add another inline policy (expect acknowledged not_reverted)
aws_ iam put-role-policy --role-name dev-extra-inline-policy-not-reverted --policy-name added-outside \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
# 5b. Change assume_role_policy (expect Drift on assume_role_policy)
aws_ iam update-assume-role-policy --role-name dev-assume-role-policy-drift --policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"lambda.amazonaws.com"}}]}'

# 6a. S3 versioning is its own resource (expect Drift on versioning_configuration)
aws_ s3api put-bucket-versioning --bucket dev-s3-separate-resources --versioning-configuration Status=Suspended
# 6b. S3 bucket policy is its own resource (expect Drift on policy)
aws_ s3api put-bucket-policy --bucket dev-s3-separate-resources --policy \
  '{"Version":"2012-10-17","Statement":[{"Sid":"AllowAll","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::dev-s3-separate-resources/*"}]}'

# 7. lifecycle.ignore_changes attribute changed outside (expect acknowledged ignore_changes)
aws_ sqs set-queue-attributes --queue-url "$(queue_url dev-ignore-changes-visibility)" --attributes VisibilityTimeout=90

# 8. for_each keys with special characters (expect Drift on addresses with odd keys)
for name in pipe angle dots quote; do
  aws_ sqs set-queue-attributes --queue-url "$(queue_url "dev-odd-key-$name")" --attributes VisibilityTimeout=45
done

# 9. Resource deleted outside Terraform (expect Drift: apply would create it again)
aws_ sqs delete-queue --queue-url "$(queue_url dev-deleted-outside-terraform)"

# prod: a second environment row in the HTML map
aws_ sqs set-queue-attributes --queue-url "$(queue_url prod-scalar-attribute-drift)" --attributes VisibilityTimeout=60
aws_ iam put-role-policy --role-name prod-extra-inline-policy-not-reverted --policy-name added-outside \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'

echo "outside changes done"
