# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM debian:11-slim

RUN apt-get update && apt-get install -y curl gnupg make

RUN curl -sS https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor > /etc/apt/trusted.gpg.d/llvm.gpg && \
    echo "deb [signed-by=/etc/apt/trusted.gpg.d/llvm.gpg] http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-15 main" >> /etc/apt/sources.list.d/llvm.list && \
    echo "deb-src [signed-by=/etc/apt/trusted.gpg.d/llvm.gpg] http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-15 main" >> /etc/apt/sources.list.d/llvm.list

RUN apt-get update && apt-get install -y clang-15 lld-15

ADD https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-17/wasi-sysroot-17.0.tar.gz /
RUN tar -xf wasi-sysroot-17.0.tar.gz

ADD https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-17/libclang_rt.builtins-wasm32-wasi-17.0.tar.gz /
# APT repository and package only include major version but the directory includes a patch version.
# We use a wildcard to make this compatible for any patch version.
RUN tar -xf libclang_rt.builtins-wasm32-wasi-17.0.tar.gz -C /usr/lib/llvm-15/lib/clang/15.*/

ENV CC clang-15
ENV CXX clang++-15
ENV LD wasm-ld-15
ENV AR llvm-ar-15
ENV RANLIB llvm-ranlib-15
ENV CFLAGS -O3 --target=wasm32-wasi --sysroot=/wasi-sysroot
ENV CXXFLAGS -O3 -fno-exceptions --target=wasm32-wasi --sysroot=/wasi-sysroot
ENV LDFLAGS ${CXXFLAGS} --rtlib=compiler-rt -Wl,--demangle,--allow-undefined
