FROM gcr.io/oss-fuzz-base/base-builder-go:latest@sha256:db46af0d66c297dce2be95304f7a12c4e0f2901fbe21f2fc10a1de19d06c5cf9

RUN git clone --depth=1 https://github.com/Mindburn-Labs/helm-ai-kernel $SRC/helm-ai-kernel

COPY build.sh $SRC/build.sh

WORKDIR $SRC/helm-ai-kernel
