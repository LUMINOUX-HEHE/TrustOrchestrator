output "cluster_name" {
  value = google_container_cluster.main.name
}

output "cluster_endpoint" {
  value = google_container_cluster.main.endpoint
}

output "kubeconfig" {
  description = "kubectl access command"
  value       = "gcloud container clusters get-credentials ${var.cluster_name} --region ${var.region} --project ${var.project}"
}

output "gateway_service" {
  value = "kubectl -n trust-orchestrator port-forward svc/gateway 8080:8080"
}
