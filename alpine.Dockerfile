FROM ghcr.io/napi-rs/napi-rs/nodejs-rust:lts-alpine

RUN apk add --update --no-cache m4

LABEL org.opencontainers.image.source=https://github.com/HuanCheng65/node-srp-rs
