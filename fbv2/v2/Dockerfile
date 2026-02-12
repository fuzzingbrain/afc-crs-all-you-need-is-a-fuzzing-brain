FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git git-lfs curl build-essential openssh-client ca-certificates gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /root/.ssh \
    && ssh-keyscan github.com gitlab.com bitbucket.org >> /root/.ssh/known_hosts 2>/dev/null \
    && git lfs install

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY fuzzingbrain/ fuzzingbrain/

ENV RUNNING_IN_DOCKER=true
ENTRYPOINT ["python3", "-m", "fuzzingbrain.main"]
