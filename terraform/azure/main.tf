terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm    = { source = "hashicorp/azurerm", version = "~> 4.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.23" }
    helm       = { source = "hashicorp/helm", version = "~> 2.12" }
    random     = { source = "hashicorp/random", version = "~> 3.5" }
  }
}

provider "azurerm" {
  features {}
}

resource "random_pet" "suffix" {
  length = 2
}

# --- Resource group + AKS cluster ---
resource "azurerm_resource_group" "main" {
  name     = "rg-${var.cluster_name}-${random_pet.suffix.id}"
  location = var.location
}

resource "azurerm_kubernetes_cluster" "main" {
  name                = "${var.cluster_name}-${random_pet.suffix.id}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = var.cluster_name

  default_node_pool {
    name       = "default"
    node_count = var.node_count
    vm_size    = var.vm_size
  }

  identity { type = "SystemAssigned" }
}

# --- Kubernetes + Helm providers (admin kubeconfig, auto-created) ---
provider "kubernetes" {
  host                   = azurerm_kubernetes_cluster.main.kube_admin_config[0].host
  client_certificate     = base64decode(azurerm_kubernetes_cluster.main.kube_admin_config[0].client_certificate)
  client_key             = base64decode(azurerm_kubernetes_cluster.main.kube_admin_config[0].client_key)
  cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.main.kube_admin_config[0].cluster_ca_certificate)
}

provider "helm" {
  kubernetes {
    host                   = azurerm_kubernetes_cluster.main.kube_admin_config[0].host
    client_certificate     = base64decode(azurerm_kubernetes_cluster.main.kube_admin_config[0].client_certificate)
    client_key             = base64decode(azurerm_kubernetes_cluster.main.kube_admin_config[0].client_key)
    cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.main.kube_admin_config[0].cluster_ca_certificate)
  }
}

# --- Deploy the chart ---
resource "helm_release" "trust_orchestrator" {
  name             = "trust-orchestrator"
  namespace        = "trust-orchestrator"
  create_namespace = true
  chart            = var.chart_path

  set {
    name  = "image.repository"
    value = var.image
  }
  set {
    name  = "gateway.adminToken"
    value = var.admin_token
  }
}
