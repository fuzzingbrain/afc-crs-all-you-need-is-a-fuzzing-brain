# SPDX-License-Identifier: Apache-2.0
docker build -f Dockerfile.analysis -t crs-analysis:latest .
docker tag crs-analysis:latest ghcr.io/parasol-aser/crs-analysis:latest
docker push ghcr.io/parasol-aser/crs-analysis:latest
kubectl set image deployment/crs-analysis -n crs-webservice crs-analysis=ghcr.io/parasol-aser/crs-analysis:latest
kubectl rollout restart deployment crs-analysis -n crs-webservice