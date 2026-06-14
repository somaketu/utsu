# Stage 1: The Rust Build Environment
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y curl build-essential
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
# Copy the entire project so Maturin can bundle the Python files and Rust binary into ONE wheel
COPY . .

RUN pip install --upgrade pip maturin
# Build the full package wheel (Python + Rust) and output it cleanly to /build/wheels
RUN export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 && maturin build --release --out /build/wheels

# Stage 2: The Lightweight Execution Container
FROM python:3.12-slim

# Install system dependencies and the Subfinder binary
RUN apt-get update && apt-get install -y wget unzip && rm -rf /var/lib/apt/lists/*
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && \
    unzip subfinder_2.6.6_linux_amd64.zip && \
    mv subfinder /usr/local/bin/ && \
    rm subfinder_2.6.6_linux_amd64.zip

WORKDIR /app

# Pull ONLY the compiled wheel from the builder stage
COPY --from=builder /build/wheels/*.whl /tmp/

# Installing the wheel automatically installs the framework and fetches all PyPI dependencies
RUN pip install /tmp/*.whl

# Set the framework as the default executable
ENTRYPOINT ["utsu"]
