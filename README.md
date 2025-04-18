# ebpf-rust-poc

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package ebpf-rust-poc --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/ebpf-rust-poc` can be
copied to a Linux server or VM and run there.

---
### install metrics server
sudo snap install helm --classic 
```
helm repo add metrics-server https://kubernetes-sigs.github.io/metrics-server 
helm repo update
helm upgrade --install --set args={--kubelet-insecure-tls} metrics-server metrics-server/metrics-server --namespace kube-system
```

### Notes
* broke something when trying to add filtering for tgid/pid

### Deploying the POC
```
// build image
docker build -t ebpf-rust-poc:latest .

// load image into kind cluster
kind load docker-image ebpf-rust-poc:latest

// also load host pod for malloc/free on the cluster

kubectl apply -f pod.yaml
// viewing the logs/metrics... atm only exported to stdout

kubectl logs -n kube-system -f <ebpf-pod>
```

1. ebpf runs at host level.
2. user space program will see the proper container id via the volume mount in /proc/<pid>/cgroup
3. kind will see the host pid - above the kind node and on the actual host - in this case my ubuntu vm processes.
```
So this is the hierarchy in kind and why we are facing an issue
[Real Host Machine]
├── PID 959533 (docker-containerd)  ← eBPF sees this level
│   └── [Kind Node Container]
│       ├── PID 10477 (kubelet)     ← Your pod's /proc shows this level
│       └── [Pod Containers]
│           ├── PID 1 (container entrypoint)
│           └── PID 1887 (your app)

some workaround is to mount the /proc directory to kind cluster
```
