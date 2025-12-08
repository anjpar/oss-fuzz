FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make

# Clone the lwIP fork with fuzzer support
RUN git clone --depth 1 https://github.com/anjpar/lwip.git lwip

WORKDIR lwip
COPY build.sh $SRC/
