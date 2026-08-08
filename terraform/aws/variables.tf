variable "region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "EKS cluster name"
  default     = "trust-orchestrator"
}

variable "node_count" {
  description = "EKS node group desired size"
  default     = 3
}

variable "instance_type" {
  description = "EKS node instance type"
  default     = "t3.medium"
}

variable "image" {
  description = "Container image in ECR (push first: make docker-build && docker tag ... && docker push)"
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
