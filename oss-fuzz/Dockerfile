FROM gcr.io/oss-fuzz-base/base-builder-go:latest@sha256:5fdc08e6006edce0de4f9bc0c3e08b3b5e6ef2841093b996858f5abbfd281f50

RUN git clone --depth=1 https://github.com/Mindburn-Labs/helm-oss $SRC/helm-oss

COPY build.sh $SRC/build.sh

WORKDIR $SRC/helm-oss
