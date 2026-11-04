terraform {
  required_version = ">= 1.5"

  backend "local" {
    path = "terraform.tfstate"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.100.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  s3_use_path_style           = true

  endpoints {
    ec2 = "http://localhost:5555"
    iam = "http://localhost:5555"
    rds = "http://localhost:5555"
    s3  = "http://localhost:5555"
    sqs = "http://localhost:5555"
    ssm = "http://localhost:5555"
    sts = "http://localhost:5555"
  }
}
