# ---- build ike-scan ----
FROM alpine:3.20 AS ikebuilder
RUN apk add --no-cache \
      build-base \
      autoconf automake libtool \
      git \
      openssl-dev
# build from upstream
RUN git clone https://github.com/royhills/ike-scan.git /src/ike-scan && \
    cd /src/ike-scan && \
    autoreconf --install && \
    ./configure --with-openssl && \
    make -j"$(nproc)" && \
    make install

# ---- runtime image ----
FROM python:3.13.9-alpine
LABEL Maintainer="LRVT"

# runtime deps for ike-scan
RUN apk add --no-cache openssl

# copy ike-scan + data files from builder
COPY --from=ikebuilder /usr/local/bin/ike-scan /usr/local/bin/ike-scan
COPY --from=ikebuilder /usr/local/bin/psk-crack /usr/local/bin/psk-crack
COPY --from=ikebuilder /usr/local/share/ike-scan /usr/local/share/ike-scan

# (optional) allow binding to privileged ports like 500/udp without root
# Uncomment if you need --sport=500 as non-root
# RUN apk add --no-cache libcap-setcap && \
#     setcap cap_net_bind_service=+ep /usr/local/bin/ike-scan

# your app
COPY ikess.py /app/
WORKDIR /app

# entrypoint runs the script; extra args from CMD are passed through
ENTRYPOINT ["python", "ikess.py"]
CMD ["--help"]
