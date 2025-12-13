.PHONY: all generate build clean run

# 默认目标
all: build

# 生成 eBPF Go 绑定代码
generate:
	export GOPACKAGE=main && go generate ./...

# 构建 Go 程序（启用静态链接优化，不依赖 libc）
build: generate
	CGO_ENABLED=0 go build -ldflags '-s -w' -o myebpf .

# 运行程序
run: build
	sudo ./myebpf

# 清理生成的文件
clean:
	rm -f myebpf
	rm -f counter_bpfeb.go counter_bpfel.go
	rm -f counter_bpfeb.o counter_bpfel.o

# 安装依赖
deps:
	go mod download
	go mod tidy

