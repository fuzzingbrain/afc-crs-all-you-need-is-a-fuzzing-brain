FROM ghcr.io/aixcc-finals/base-builder:v1.1.0
RUN apt-get update && apt-get install -y build-essential

WORKDIR $SRC
COPY pkgs/integration-test.tar.gz $SRC/
RUN tar -xzf $SRC/integration-test.tar.gz && rm $SRC/integration-test.tar.gz

COPY build.sh $SRC/
COPY fuzz_* *.options $SRC/
WORKDIR $SRC/integration-test
