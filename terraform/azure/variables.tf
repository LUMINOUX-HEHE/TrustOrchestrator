variable "location" {
  description = "Azure region"
  default     = "eastus"
}

variable "cluster_name" {
  description = "AKS cluster name prefix"
  default     = "trust-orchestrator"
}

variable "node_count" {
  description = "AKS default node pool size"
  default     = 3
}

variable "vm_size" {
  description = "AKS node VM size"
  default     = "Standard_B2ms"
}

variable "image" {
  description = "Container image in ACR (push first: make docker-build && docker tag ... && docker push)"
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
