CONTAINER_RUNTIME := docker

.PHONY: all clean quick-build quick-deploy
all: quick-clean quick-build quick-deploy

quick-clean:
	$(CONTAINER_RUNTIME) rmi -f ebpf-rust-poc:latest || true; \

quick-build:
	$(CONTAINER_RUNTIME) build -t ebpf-rust-poc:latest .; \
	kind load docker-image ebpf-rust-poc:latest; \

load-images:
	kind load docker-image ebpf-rust-poc:latest; \
	kind load docker-image test-malloc-free:latest; \

quick-deploy:
	kubectl delete -f deploy/pod.yaml; \
	kubectl apply -f deploy/pod.yaml;\

test-deploy:
	kubectl delete -f test/hostpod.yaml; \
	kubectl apply -f test/hostpod.yaml;
