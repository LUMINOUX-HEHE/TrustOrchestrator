variable "project" {
  description = "GCP project id"
}

variable "region" {
  description = "GCP region"
  default     = "us-central1"
}

variable "cluster_name" {
  description = "GKE cluster name"
  default     = "trust-orchestrator"
}

variable "node_count" {
  description = "GKE node pool size"
  default     = 3
}

variable "machine_type" {
  description = "GKE node machine type"
  default     = "e2-standard-2"
}

variable "image" {
  description = "Container image in GCR/Artifact Registry (push first: make docker-build && docker tag ... && docker push)"
  default     = "trust-orchestrator:latest"
}

variable "admin_token" {
  description = "Gateway admin bootstrap token (first boot only)"
  default     = ""
}

variable "chart_path" {
  description = "Path to the helm chart"
  default     = "../../helm/trust-orchestrator"
}
