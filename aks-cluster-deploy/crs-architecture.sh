#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -e

##set ANSI escaape codes
NC='\033[0m'
RED='\033[1;31m'
GRN='\033[1;32m'
BLU='\033[1;36m'

#executes a series of terraform, az cli, and kubernetes commands to deploy or destroy an example crs architecture

echo -e "${BLU}Applying environment variables from ./env${NC}"
# shellcheck disable=SC1094
source ./env
echo -e "${GRN}Current azure account status:${NC}"
az account show --query "{SubscriptionID:id, Tenant:tenantId}" --output table

#deploy the AKS cluster and kubernetes resources function
up() {

	echo -e "${BLU}Applying environment variables to yaml from templates${NC}"
	CLIENT_BASE64=$(echo -n "$TF_VAR_ARM_CLIENT_SECRET" | base64)
	CRS_KEY_BASE64=$(echo -n "$CRS_KEY_TOKEN" | base64)
	COMPETITION_API_KEY_BASE64=$(echo -n "$COMPETITION_API_KEY_TOKEN" | base64)
	export CLIENT_BASE64
	export CRS_KEY_BASE64
	export COMPETITION_API_KEY_BASE64
	export TS_DNS_IP
	envsubst <k8s/base/crs-webservice/ingress.template >k8s/base/crs-webservice/ingress.yaml
	envsubst <k8s/base/crs-webservice/.dockerconfigjson.template >k8s/base/crs-webservice/.dockerconfigjson
	envsubst <k8s/base/crs-webservice/secrets.template >k8s/base/crs-webservice/secrets.yaml
	envsubst <k8s/base/crs-webservice/deployment.template >k8s/base/crs-webservice/deployment.yaml
	envsubst <k8s/base/tailscale-operator/operator.template >k8s/base/tailscale-operator/operator.yaml

	#deploy AKS resources in Azure
	echo -e "${BLU}Deploying AKS cluster Resources${NC}"
	terraform init
	terraform apply -auto-approve

	#set resource group name and kubernetes cluster name variables from terraform outputs

	KUBERNETES_CLUSTER_NAME=$(terraform output -raw kubernetes_cluster_name)
	RESOURCE_GROUP_NAME=$(terraform output -raw resource_group_name)

	echo -e "${GRN}KUBERNETES_CLUSTER_NAME is $KUBERNETES_CLUSTER_NAME"
	echo "RESOURCE_GROUP_NAME is $RESOURCE_GROUP_NAME${NC}"
	echo -e "${BLU}Retrieving credentials to access AKS cluster${NC}"
	#retrieve credentials to access AKS cluster

	az aks get-credentials --resource-group "$RESOURCE_GROUP_NAME" --name "$KUBERNETES_CLUSTER_NAME"

	#deploy kubernetes resources in AKS cluster
	kubectl apply -k k8s/base/tailscale-operator/
	kubectl apply -k k8s/base/tailscale-dns/

	echo -e "${BLU}Waiting for the service nameserver to exist${NC}"
	timeout 5m bash -c "until kubectl get svc -n tailscale nameserver > /dev/null 2>&1; do sleep 1; done" || echo -e "${RED}Error: nameserver failed to exist within 5 minutes${NC}"
	echo -e "${BLU}Waiting for nameserver to have a valid ClusterIP${NC}"
	timeout 5m bash -c "until kubectl get svc -n tailscale nameserver -o jsonpath='{.spec.clusterIP}' | grep -v '<none>' > /dev/null 2>&1; do sleep 1; done" || echo -e "${RED}Error: nameserver failed to obtain a valid CLusterIP within 5 minutes${NC}"
	TS_DNS_IP=$(kubectl get svc -n tailscale nameserver -o jsonpath='{.spec.clusterIP}')
	envsubst <k8s/base/tailscale-coredns/coredns-custom.template >k8s/base/tailscale-coredns/coredns-custom.yaml

	kubectl apply -k k8s/base/tailscale-coredns/
	kubectl apply -k k8s/base/crs-webservice/
	kubectl apply -k k8s/base/tailscale-connections/

	echo -e "${BLU}Waiting for ingress hostname DNS registration${NC}"
	timeout 5m bash -c "until kubectl get ingress -n crs-webservice crs-webapp -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' | grep -q '.'; do sleep 1; done" || echo -e "${BLU}Error: Ingress hostname failed to be to set within 5 minutes${NC}"
	INGRESS_HOSTNAME=$(kubectl get ingress -n crs-webservice crs-webapp -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
	echo -e "${GRN}Your ingress DNS hostname is $INGRESS_HOSTNAME${NC}"

}

#destroy the AKS cluster and kubernetes resources function
down() {
	echo -e "${BLU}Deleting Kubernetes resource${NC}"
	set +e
	kubectl delete -k k8s/base/tailscale-connections/
	kubectl delete -k k8s/base/crs-webservice/
	timeout 2m bash -c "until kubectl get statefulset -n tailscale -l tailscale.com/parent-resource=crs-webapp,tailscale.com/parent-resource-ns=crs-webservice 2>&1 | grep -q 'No resources found'; do sleep 1; done" || echo -e "${RED}Error: StatefulSet cleanup timed out after 2 minutes${NC}"
	kubectl delete -k k8s/base/tailscale-coredns/
	kubectl delete -k k8s/base/tailscale-dns/
	kubectl delete -k k8s/base/tailscale-operator/
	set -e
	echo -e "${BLU}Destroying AKS cluster${NC}"
	terraform apply -destroy -auto-approve

}

case $1 in
up)
	up
	;;
down)
	down
	;;
*)
	echo -e "${RED}The only acceptable arguments are up and down${NC}"
	;;
esac
