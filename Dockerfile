# Use Debian bookworm as base - good balance of stability and package availability
FROM debian:bookworm-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    perl \
    ca-certificates \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy Cargo files for dependency caching
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build program
RUN cargo build --release

# Expose the default port
EXPOSE 6188

# Run the application
ENTRYPOINT ["./target/release/mitm", "start", "-ik", "-l", "0.0.0.0:6188"]