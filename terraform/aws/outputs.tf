output "cluster_name" {
  value = aws_eks_cluster.main.name
}

output "cluster_endpoint" {
  value = aws_eks_cluster.main.endpoint
}

output "kubeconfig" {
  description = "kubectl access command (token is time-limited)"
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${var.cluster_name}"
}

output "gateway_service" {
  value = "kubectl -n trust-orchestrator port-forward svc/gateway 8080:8080"
}
