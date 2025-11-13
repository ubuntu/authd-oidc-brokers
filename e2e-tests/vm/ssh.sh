#!/usr/bin/env sh

exec ssh \
  -o ProxyCommand="socat - VSOCK-CONNECT:1000:22" \
  -o UserKnownHostsFile=/dev/null \
  -o StrictHostKeyChecking=no \
  -o LogLevel=ERROR \
  ubuntu@localhost "$@"
