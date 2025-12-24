.PHONY: all generate build clean

# 默认目标
all: build

# 生成 eBPF Go 绑定代码
generate:
	cd ebpf && go generate -tags linux ./...

# 构建 Go 程序（启用静态链接优化，不依赖 libc）
build-flow_demo: generate
	CGO_ENABLED=0 && go build  -ldflags '-s -w' -o bin/flow_demo ./flow_demo

build-counter_demo: generate
	CGO_ENABLED=0 && go build  -ldflags '-s -w' -o bin/counter_demo ./counter_demo

build: build-flow_demo build-counter_demo

# 清理生成的文件
clean:
	rm -f bin/
	rm -f ebpf/counter/counter_bpfeb.go ebpf/counter/counter_bpfeb.o ebpf/counter/counter_bpfel.go ebpf/counter/counter_bpfel.o
	rm -f ebpf/flow/flow_bpfeb.go ebpf/flow/flow_bpfeb.o ebpf/flow/flow_bpfel.go ebpf/flow/flow_bpfel.o