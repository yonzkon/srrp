#!/bin/bash

srrpr() {
    cargo build --manifest-path=./rust-srrpr/Cargo.toml
    ./rust-srrpr/target/debug/srrpr -d
}

srrpr-websocket-proxy() {
    cargo build --manifest-path=./rust-srrpr-websocket-proxy/Cargo.toml
    ./rust-srrpr-websocket-proxy/target/debug/srrpr-websocket-proxy -d
}

case $1 in
srrpr) srrpr;;
proxy) srrpr-websocket-proxy;;
*) exit 1;;
esac

exit 0
