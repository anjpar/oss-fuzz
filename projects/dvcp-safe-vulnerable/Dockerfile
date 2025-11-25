FROM gcr.io/oss-fuzz-base/base-builder
WORKDIR /src

# Clone the challenge repository
RUN git clone --depth 1 https://github.com/anjpar/dvcp-safe-and-vulnerable.git dvcp

# Copy build script and fuzzer from the challenge repo
RUN cp dvcp/contrib/oss-fuzz/build.sh $SRC
RUN chmod +x $SRC/build.sh

WORKDIR dvcp
