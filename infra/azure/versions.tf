terraform {
  required_version = ">= 1.9"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 5.7" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
  }
  # backend "azurerm" {}   # configure remote state (storage account + container) before first apply
}

provider "azurerm" {
  features {
    key_vault { purge_soft_delete_on_destroy = false }
  }
  storage_use_azuread = true
}
