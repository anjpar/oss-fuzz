FROM gcr.io/oss-fuzz-base/base-builder
WORKDIR /src

# Fetch the DVCP sources into /src/dvcp
RUN git clone https://github.com/hardik05/Damn_Vulnerable_C_Program.git dvcp

# Make sure the runner can find the build script
COPY build.sh /src/build.sh
RUN chmod +x /src/build.sh

# --- Ensure Buttercup's scheduler sees artifacts in <attempt>/out ---
# Buttercup will mount the attempt root at /workspace (next step),
# so mirror OSS-Fuzz /out into /workspace/out.
RUN mkdir -p /workspace/out && cp -r /out/* /workspace/out/ || true
