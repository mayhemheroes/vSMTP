# Build Stage
FROM ghcr.io/evanrichter/cargo-fuzz:latest as builder

## Dependencies
RUN apt update && apt install -y libgsasl7-dev

## Add source code to the build stage.
ADD . /src
WORKDIR /src

RUN echo building instrumented harnesses && \
    bash -c "pushd fuzz && cargo +nightly -Z sparse-registry fuzz build && popd" && \
    mv fuzz/target/x86_64-unknown-linux-gnu/release/receiver /receiver && \
    mv fuzz/target/x86_64-unknown-linux-gnu/release/rules /rules && \
    mv fuzz/target/x86_64-unknown-linux-gnu/release/server_config /server_config && \
    mv fuzz/target/x86_64-unknown-linux-gnu/release/mime_parser /mime_parser && \
    echo done

RUN echo building non-instrumented harnesses && \
    export RUSTFLAGS="--cfg fuzzing -Clink-dead-code -Cdebug-assertions -C codegen-units=1" && \
    bash -c "pushd fuzz && cargo +nightly -Z sparse-registry build --release && popd" && \
    mv fuzz/target/release/receiver /receiver_no_inst && \
    mv fuzz/target/release/rules /rules_no_inst && \
    mv fuzz/target/release/server_config /server_config_no_inst && \
    mv fuzz/target/release/mime_parser /mime_parser_no_inst && \
    echo done

# Package Stage
FROM rustlang/rust:nightly

RUN useradd vsmtp
COPY --from=builder \
    /usr/lib/libgsasl.so.7 \
    /lib/x86_64-linux-gnu/libidn.so.11 \
    /usr/lib/x86_64-linux-gnu/libntlm.so.0 \
    /usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2 \
    /usr/lib/x86_64-linux-gnu/libkrb5.so.3 \
    /usr/lib/x86_64-linux-gnu/libk5crypto.so.3 \
    /lib/x86_64-linux-gnu/libcom_err.so.2 \
    /usr/lib/x86_64-linux-gnu/libkrb5support.so.0 \
    /lib/x86_64-linux-gnu/libkeyutils.so.1 \
    /lib/x86_64-linux-gnu/libresolv.so.2 \
    /usr/lib/

COPY --from=builder /receiver /receiver_no_inst \
                    /rules /rules_no_inst \
                    /server_config /server_config_no_inst \
                    /mime_parser /mime_parser_no_inst /
