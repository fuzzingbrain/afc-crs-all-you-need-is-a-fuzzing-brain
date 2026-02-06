FROM ubuntu:22.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    docker.io \
    sudo \
    libclang-dev \
    openjdk-17-jdk \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Joern
RUN curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" -o joern-install.sh \
    && chmod +x joern-install.sh \
    && ./joern-install.sh --install-dir=/opt/joern \
    && rm joern-install.sh
ENV PATH="/opt/joern/joern-cli/bin:${PATH}"

# Install Go 1.21 and create symlinks for sudo compatibility
RUN wget -q https://go.dev/dl/go1.21.13.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.13.linux-amd64.tar.gz \
    && rm go1.21.13.linux-amd64.tar.gz \
    && ln -s /usr/local/go/bin/go /usr/local/bin/go \
    && ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt
ENV PATH="/usr/local/go/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app/

# Install Python dependencies globally
RUN pip3 install --no-cache-dir \
    loguru>=0.7.0 \
    typing-extensions>=4.8.0 \
    litellm>=1.0.0 \
    google-generativeai \
    openlit>=1.0.0 \
    clang>=14.0 \
    requests>=2.31.0 \
    python-dotenv>=1.0.0 \
    anthropic \
    openai \
    claude-agent-sdk

# Create workspace directory
RUN mkdir -p /app/workspace

# Make scripts executable
RUN chmod +x FuzzingBrain.sh crs/run_crs.sh

# Skip venv creation (deps are pre-installed globally)
ENV SKIP_VENV=true
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/app/FuzzingBrain.sh"]
