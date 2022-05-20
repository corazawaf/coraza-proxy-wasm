FROM scratch

LABEL org.opencontainers.image.source=https://github.com/jcchavezs/coraza-wasm-filter

COPY build/main.wasm /plugin.wasm