FROM gcr.io/oss-fuzz-base/base-builder-go:latest@sha256:a6a7b6569fb3dfde907aafcbdd31fbb9e6004def002b108cca7bfaafd39e1a91

RUN git clone --depth=1 https://github.com/Mindburn-Labs/helm-ai-kernel $SRC/helm-ai-kernel

COPY build.sh $SRC/build.sh

WORKDIR $SRC/helm-ai-kernel
