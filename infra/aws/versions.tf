terraform {
  required_version = ">= 1.9"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 6.10" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
  # backend "s3" {}   # remote state with locking before the first apply
}

provider "aws" {
  region = var.region
  default_tags { tags = var.tags }
}
