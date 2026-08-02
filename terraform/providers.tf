terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "purple-team-tfstate-yuvraj2026"
    key            = "purple-team/terraform.tfstate"
    region         = "eu-north-1"
    dynamodb_table = "purple-team-tf-lock"
    encrypt        = true
  }
}

provider "aws" {
  region = "eu-north-1"
}
