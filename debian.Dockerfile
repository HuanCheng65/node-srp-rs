FROM ghcr.io/napi-rs/napi-rs/nodejs-rust:lts-debian

RUN apt-get update && \
    apt-get install -y \
    m4 \
    libgmp-dev \
    libc6-dev \
    gcc \
    build-essential

# 修复 glibc 开发头文件以支持交叉编译
# RUN cd /usr/include && \
#     grep -l "__GLIBC_USE" *.h | xargs -I{} cp {} /usr/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/sysroot/usr/include/ && \
#     cp features.h /usr/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/sysroot/usr/include/ && \
#     cp -r bits /usr/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/sysroot/usr/include/ && \
#     cp -r gnu /usr/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/sysroot/usr/include/

# 设置环境变量以避免编译时路径混乱
ENV GMP_MPFR_SYS_USE_SYSTEM_LIBS=1 \
    C_INCLUDE_PATH="/usr/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/sysroot/usr/include"

LABEL org.opencontainers.image.source=https://github.com/HuanCheng65/node-srp-rs
