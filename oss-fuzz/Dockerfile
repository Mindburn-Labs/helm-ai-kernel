FROM gcr.io/oss-fuzz-base/base-builder-go:latest

RUN git clone --depth=1 https://github.com/Mindburn-Labs/helm-oss $SRC/helm-oss

COPY build.sh $SRC/build.sh

WORKDIR $SRC/helm-oss
