output "cluster_name" {
  value = azurerm_kubernetes_cluster.main.name
}

output "resource_group" {
  value = azurerm_resource_group.main.name
}

output "kubeconfig" {
  description = "kubectl access command"
  value       = "az aks get-credentials --resource-group ${azurerm_resource_group.main.name} --name ${azurerm_kubernetes_cluster.main.name}"
}

output "gateway_service" {
  value = "kubectl -n trust-orchestrator port-forward svc/gateway 8080:8080"
}
