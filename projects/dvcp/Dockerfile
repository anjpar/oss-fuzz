FROM gcr.io/oss-fuzz-base/base-builder
WORKDIR /src

# Fetch the DVCP sources into /src/dvcp
RUN git clone https://github.com/hardik05/Damn_Vulnerable_C_Program.git dvcp

# Make sure the runner can find the build script
COPY build.sh /src/build.sh
RUN chmod +x /src/build.sh

