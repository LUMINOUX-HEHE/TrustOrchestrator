terraform {
  required_version = ">= 1.5"
  required_providers {
    google     = { source = "hashicorp/google", version = "~> 6.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.23" }
    helm       = { source = "hashicorp/helm", version = "~> 2.12" }
  }
}

provider "google" {
  project = var.project
  region  = var.region
}

data "google_client_config" "default" {}

# --- VPC + subnet for the GKE cluster ---
resource "google_compute_network" "main" {
  name                    = "${var.cluster_name}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "main" {
  name                     = "${var.cluster_name}-subnet"
  network                  = google_compute_network.main.id
  region                   = var.region
  ip_cidr_range            = "10.0.0.0/16"
  private_ip_google_access = true
}

# --- GKE cluster (regional, private node pools) ---
resource "google_container_cluster" "main" {
  name     = var.cluster_name
  location = var.region

  network    = google_compute_network.main.id
  subnetwork = google_compute_subnetwork.main.id

  remove_default_node_pool = true
  initial_node_count       = 1
}

resource "google_container_node_pool" "main" {
  name       = "main"
  location   = var.region
  cluster    = google_container_cluster.main.name
  node_count = var.node_count

  node_config {
    machine_type = var.machine_type
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]
  }
}

# --- Kubernetes + Helm providers (ephemeral access token) ---
provider "kubernetes" {
  host                   = "https://${google_container_cluster.main.endpoint}"
  cluster_ca_certificate = base64decode(google_container_cluster.main.master_auth[0].cluster_ca_certificate)
  token                  = data.google_client_config.default.access_token
}

provider "helm" {
  kubernetes {
    host                   = "https://${google_container_cluster.main.endpoint}"
    cluster_ca_certificate = base64decode(google_container_cluster.main.master_auth[0].cluster_ca_certificate)
    token                  = data.google_client_config.default.access_token
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
