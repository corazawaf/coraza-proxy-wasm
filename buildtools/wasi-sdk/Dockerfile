# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM debian:11-slim

RUN apt-get update && apt-get install -y curl gnupg make

RUN curl -sS https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor > /etc/apt/trusted.gpg.d/llvm.gpg && \
    echo "deb [signed-by=/etc/apt/trusted.gpg.d/llvm.gpg] http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-14 main" >> /etc/apt/sources.list.d/llvm.list && \
    echo "deb-src [signed-by=/etc/apt/trusted.gpg.d/llvm.gpg] http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-14 main" >> /etc/apt/sources.list.d/llvm.list

RUN apt-get update && apt-get install -y clang-14 lld-14

ADD https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-16/wasi-sysroot-16.0.tar.gz /
RUN tar -xf wasi-sysroot-16.0.tar.gz

ADD https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-16/libclang_rt.builtins-wasm32-wasi-16.0.tar.gz /
RUN tar -xf libclang_rt.builtins-wasm32-wasi-16.0.tar.gz -C /usr/lib/llvm-14/lib/clang/14.0.6/

ENV CC clang-14
ENV CXX clang++-14
ENV LD wasm-ld-14
ENV AR llvm-ar-14
ENV RANLIB llvm-ranlib-14
ENV CFLAGS -O3 --target=wasm32-wasi --sysroot=/wasi-sysroot
ENV CXXFLAGS -O3 -fno-exceptions --target=wasm32-wasi --sysroot=/wasi-sysroot
ENV LDFLAGS ${CXXFLAGS} --rtlib=compiler-rt -Wl,--demangle,--allow-undefined
