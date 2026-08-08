# Terraform: AWS / Azure / GCP

Each directory is a standalone module: network → managed Kubernetes cluster
(EKS/AKS/GKE) → node pool → Helm-deploys `helm/trust-orchestrator`.

## Before you start

1. Build and push the image to the cloud's registry:

   ```sh
   make docker-build
   docker tag trust-orchestrator:latest <registry>/trust-orchestrator:latest
   docker push <registry>/trust-orchestrator:latest
   ```

2. Do the offline bootstrap ceremony (root key, FROST shares, CA, node
   certs) — exactly as documented in `helm/trust-orchestrator/values.yaml`
   — and put the material into the chart values (or a `helm_values.yaml`
   overlay).
3. Authenticate: `aws configure` / `az login` / `gcloud auth application-default login`.

## Apply

```sh
cd terraform/aws      # or azure / gcp
terraform init
terraform plan -var admin_token=$(openssl rand -hex 32) -var image=<registry>/trust-orchestrator:latest
terraform apply -auto-approve -var admin_token=$(openssl rand -hex 32) -var image=<registry>/trust-orchestrator:latest
```

Then use the printed outputs: kubeconfig command + gateway port-forward.

Notes (ponytail: known ceilings, not bugs):
- AWS provider token comes from `data.aws_eks_cluster_auth` and expires
  (≈15 min). Re-run `terraform apply` or use `aws eks update-kubeconfig`
  for interactive sessions.
- Bootstrap material (FROST shares, CA, node keys) lives in chart values, then in
  Kubernetes Secrets. Outside of the repo — keep it that way.
- PVs use the cluster's default storage class (gp2/ebs, managed-disk,
  standard-rwo). Pin a `storageClassName` in chart values to override.
