terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
  required_providers {
    local = {
      source = "hashicorp/local"
    }
  }
}

resource "local_file" "config" {
  filename = "${path.module}/out/config.txt"
  content  = "port=8080\n"
}
