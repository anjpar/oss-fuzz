FROM gcr.io/oss-fuzz-base/base-builder
WORKDIR /src

# Clone the vulnerable C program repository
RUN git clone --depth 1 https://github.com/anjpar/dvcp-safe-and-vulnerable.git dvcp

# Copy build files
COPY build.sh /src/build.sh
COPY dvcp_fuzz_linked.c /src/dvcp_fuzz_linked.c
RUN chmod +x /src/build.sh

# Ensure Buttercup's scheduler sees artifacts
RUN mkdir -p /workspace/out && cp -r /out/* /workspace/out/ || true
