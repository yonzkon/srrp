# Srrp

To write a srrp router in C.
```c
struct cio_listener *unix_listener = cio_listener_bind("unix:///tmp/srrp");
struct cio_listener *tcp_listener = cio_listener_bind("tcp://127.0.0.1:3824");

struct srrp_router *router = srrpr_new();
srrpr_add_listener(router, unix_listener, 1, "router-unix");
srrpr_add_listener(router, tcp_listener, 1, "router-tcp");

for (;;) {
    if (srrpr_wait(router, 10 * 1000) == 0) {
        continue;
    }
    struct srrp_packet *pac;
    while ((pac = srrpr_iter(router))) {
        if (strcmp(srrp_get_dstid(pac), "router-unix") != 0 &&
            strcmp(srrp_get_dstid(pac), "router-tcp") != 0) {
            srrpr_forward(router, pac);
        }
    }
}

srrpr_drop(router); // auto close all fd
```

To write a simple srrp client in Rust.
```rust
let client = cio::CioStream::connect("unix:///tmp/srrp").unwrap();
let conn = srrp::SrrpConnect::new(client, "test-client").unwrap();

// send back to self
let req = srrp::Srrp::new_request(
    "test-client", "test-client", "/hello", "{\"msg\":\"world\"}").unwrap();
conn.send(&req);

// wait until received one or more packet
conn.wait_until();

// fetch the packet and print the raw content
let pac = conn.iter().unwrap();
println!("{}", std::str::from_utf8(&pac.raw).unwrap());
```

[![Build status](
https://ci.appveyor.com/api/projects/status/vilmj1a3q2qg2ph0?svg=true)](https://ci.appveyor.com/project/yonzkon/srrp)

Lightweight message broker that use simple request response protocol(srrp).

## Packet format

```
Ctrl: =[fin][ver2][payload_type]#[packet_len]#[payload_len]#[srcid]#0:[/anchor]?[payload]\0<crc16>\0
  =101j#[packet_len]#[payload_len]#F1#0:/sync?{"alias":["google.com","a.google.com","b.google.com"]}\0<crc16>\0

Request: >[fin][ver2][payload_type]#[packet_len]#[payload_len]#[srcid]#[dstid]:[/anchor]?[payload]\0<crc16>\0
  >001j#[packet_len]#[payload_len]#F1#8A8F:/echo?{"err":0,\0<crc16>\0
  >101j#[packet_len]#[payload_len]#F1#8A8F:/echo?"msg":"ok"}\0<crc16>\0

Response: <[fin][ver2][payload_type]#[packet_len]#[payload_len]#[srcid]#[dstid]:[/anchor]?[payload]\0<crc16>\0
  <101j#[packet_len]#[payload_len]#8A8F#F1:/echo?{"err":0,"msg":"ok","v":"good news"}\0<crc16>\0

Subscribe: +[fin][ver2][payload_type]#[packet_len]#[payload_len]:[/anchor]?[payload]\0<crc16>\0
  +101j#[packet_len]#0:/motor/speed\0<crc16>\0

UnSubscribe: -[fin][ver2][payload_type]#[packet_len]#[payload_len]:[/anchor]?[payload]\0<crc16>\0
  -101j#[packet_len]#0:/motor/speed\0<crc16>\0

Publish: @[fin][ver2][payload_type]#[packet_len]#[payload_len]:[/anchor]?[payload]\0<crc16>\0
  @101j#[packet_len]#[payload_len]:/motor/speed?{"speed":12,"voltage":24}\0<crc16>\0
```

## Dependencies

- [Cio](https://github.com/yonzkon/cio)

## Supported platforms

- Linux
- MacOS
- MinGW

## Build
```
mkdir build && cd build
cmake ..
make && make install
```
