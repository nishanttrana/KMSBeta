packer {
  required_version = ">= 1.10.0"

  required_plugins {
    vmware = {
      source  = "github.com/hashicorp/vmware"
      version = ">= 1.1.0"
    }
  }
}

variable "vm_name" {
  type    = string
  default = "vecta-kms-appliance"
}

variable "cpus" {
  type    = number
  default = 8
}

variable "memory" {
  type    = number
  default = 16384
}

variable "disk_size_mb" {
  type    = number
  default = 122880
}

variable "ssh_username" {
  type    = string
  default = "packer"
}

variable "ssh_password" {
  type    = string
  default = "packer"
}

variable "iso_url" {
  type    = string
  default = "https://releases.ubuntu.com/24.04.3/ubuntu-24.04.3-live-server-amd64.iso"
}

variable "iso_checksum" {
  type    = string
  default = "sha256:REPLACE_WITH_UBUNTU_24_04_SHA256"
}

variable "source_directory" {
  type    = string
  default = "."
}

variable "output_directory" {
  type    = string
  default = "infra/packer/output"
}

variable "headless" {
  type    = bool
  default = true
}

locals {
  ovf_dir = "${var.output_directory}/${var.vm_name}"
}

source "vmware-iso" "vecta_kms" {
  vm_name       = var.vm_name
  guest_os_type = "ubuntu-64"

  cpus      = var.cpus
  memory    = var.memory
  disk_size = var.disk_size_mb

  iso_url      = var.iso_url
  iso_checksum = var.iso_checksum

  communicator = "ssh"
  ssh_username = var.ssh_username
  ssh_password = var.ssh_password
  ssh_timeout  = "30m"

  headless           = var.headless
  output_directory   = local.ovf_dir
  shutdown_command   = "echo '${var.ssh_password}' | sudo -S shutdown -P now"

  http_directory = "infra/packer/http"
  boot_wait      = "5s"
  boot_command = [
    "c<wait>",
    "linux /casper/vmlinuz autoinstall ds='nocloud-net;seedfrom=http://{{ .HTTPIP }}:{{ .HTTPPort }}/' ---<enter>",
    "initrd /casper/initrd<enter>",
    "boot<enter>"
  ]
}

build {
  name    = "vecta-kms-ova"
  sources = ["source.vmware-iso.vecta_kms"]

  provisioner "file" {
    source      = var.source_directory
    destination = "/tmp/vecta-kms-src"
  }

  provisioner "shell" {
    scripts = [
      "infra/packer/scripts/base.sh",
      "infra/packer/scripts/install-docker.sh",
      "infra/packer/scripts/install-vecta.sh",
      "infra/packer/scripts/hardening.sh"
    ]
    environment_vars = [
      "VM_NAME=${var.vm_name}"
    ]
  }

  post-processor "shell-local" {
    script = "infra/packer/scripts/export-ova.sh"
    environment_vars = [
      "OVF_DIR=${abspath(local.ovf_dir)}",
      "VM_NAME=${var.vm_name}",
      "OUTPUT_DIR=${abspath(var.output_directory)}"
    ]
  }
}
