packer {
  required_version = ">= 1.10.0"

  required_plugins {
    virtualbox = {
      source  = "github.com/hashicorp/virtualbox"
      version = ">= 1.1.1"
    }
  }
}

variable "vm_name" {
  type    = string
  default = "vecta-kms-appliance"
}

variable "cpus" {
  type    = number
  default = 4
}

variable "memory" {
  type    = number
  default = 8192
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
  default = "file:///C:/Users/NishantRana/Downloads/KMS/ubuntu.iso"
}

variable "iso_checksum" {
  type    = string
  default = "none"
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

source "virtualbox-iso" "vecta_kms" {
  vm_name              = var.vm_name
  guest_os_type        = "Ubuntu_64"
  hard_drive_interface = "sata"
  disk_size            = var.disk_size_mb
  iso_url              = var.iso_url
  iso_checksum         = var.iso_checksum
  ssh_username         = var.ssh_username
  ssh_password         = var.ssh_password
  ssh_timeout          = "45m"
  shutdown_command     = "echo '${var.ssh_password}' | sudo -S shutdown -P now"
  headless             = var.headless
  output_directory     = "${var.output_directory}/${var.vm_name}-vbox"
  format               = "ova"
  keep_registered      = false
  http_directory       = "infra/packer/http"
  boot_wait            = "8s"

  boot_command = [
    "<esc><wait>",
    "c<wait>",
    "linux /casper/vmlinuz autoinstall ds='nocloud-net;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/' ---<enter>",
    "initrd /casper/initrd<enter>",
    "boot<enter>"
  ]

  vboxmanage = [
    ["modifyvm", "{{ .Name }}", "--memory", "${var.memory}"],
    ["modifyvm", "{{ .Name }}", "--cpus", "${var.cpus}"],
    ["modifyvm", "{{ .Name }}", "--audio-enabled", "off"],
    ["modifyvm", "{{ .Name }}", "--graphicscontroller", "vmsvga"]
  ]
}

build {
  name    = "vecta-kms-ova-vbox"
  sources = ["source.virtualbox-iso.vecta_kms"]

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
  }
}
