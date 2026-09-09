# Build the manager binary
ARG golang_image
ARG base_image

FROM $golang_image as builder

ARG TARGETOS
ARG TARGETARCH

# Env configuration
ENV GOPROXY=direct

WORKDIR /workspace

COPY go.mod go.sum ./
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

COPY . ./

# The buildx Go stage runs on BUILDPLATFORM. Cross-compile every executable for
# the image platform; these Go packages use the SDK's syscall implementation and
# do not need a cross C compiler.
RUN make build-linux GO_ARCH="${TARGETARCH}" CGO_ENABLED=0

# Vmlinux
FROM public.ecr.aws/amazonlinux/amazonlinux:2023 as vmlinuxbuilder
WORKDIR /vmlinuxbuilder
RUN yum update -y && \
    yum install -y iproute procps-ng && \
    yum install -y llvm clang make gcc && \
    yum install -y kernel-devel elfutils-libelf-devel zlib-devel libbpf-devel bpftool && \
    yum clean all
COPY . ./
RUN make vmlinuxh

# Build BPF
FROM public.ecr.aws/amazonlinux/amazonlinux:2023 as bpfbuilder
WORKDIR /bpfbuilder
RUN yum update -y && \
    yum install -y iproute procps-ng iptables && \
    yum install -y llvm clang make gcc && \
    yum install -y kernel-devel elfutils-libelf-devel zlib-devel libbpf-devel && \
    yum clean all

COPY . ./
COPY --from=vmlinuxbuilder /vmlinuxbuilder/pkg/ebpf/c/vmlinux.h ./pkg/ebpf/c/
RUN make build-bpf
RUN ./scripts/package-fqdn-netfilter.sh /fqdn-rootfs

# Container base image
FROM ${base_image}

WORKDIR /
COPY --from=bpfbuilder /fqdn-rootfs/ /
# xtables initializes netfilter even for --version. Execute it in native kernel
# qualification; the arm64 QEMU cross-build cannot open that protocol.
COPY --from=builder /workspace/controller .
COPY --from=builder /workspace/aws-eks-na-cli .
COPY --from=builder /workspace/aws-eks-na-cli-v6 .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.v4ingress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.v4egress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.v6ingress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.v6egress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/v4events.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/v6events.bpf.o .

ENTRYPOINT ["/controller"]
