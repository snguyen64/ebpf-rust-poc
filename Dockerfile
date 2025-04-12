# Stage 1: Build Stage
FROM mcr.microsoft.com/devcontainers/rust:1-bookworm AS builder

# Install dependencies for building eBPF programs
RUN apt-get update \
  && apt install -y lsb-release wget software-properties-common gnupg protobuf-compiler \
  && wget https://apt.llvm.org/llvm.sh \
  && chmod a+x llvm.sh \
  && ./llvm.sh 20 all \
  && apt install -y libclang-20-dev libpolly-20-dev libzstd-dev bpftool \
  && apt autoremove -y

# Set LLVM_SYS_201_PREFIX to point to the installed LLVM version
ENV LLVM_SYS_201_PREFIX=/usr/lib/llvm-20

# Install Rust nightly and necessary tools
RUN rustup install nightly \
  && rustup default nightly \
  && rustup component add rust-src

# Install aya tools and bpf-linker
RUN cargo install --no-default-features bpf-linker
RUN cargo install --git https://github.com/aya-rs/aya -- aya-tool

# Copy the application source code into the container
WORKDIR /app
COPY . .

# Build the eBPF program
RUN cargo build --release

# Stage 2: Runtime Stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update \
  && apt install -y libelf1 libclang-dev \
  && apt autoremove -y

# Copy the built binaries from the build stage
WORKDIR /app
COPY --from=builder /app/target/release/ebpf-rust-poc /app/ebpf-rust-poc

# Set the default command to run the application
CMD ["/app/ebpf-rust-poc"]