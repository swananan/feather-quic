# feather-quic
A tiny QUIC implementation in Rust

[中文](./README.md)

feather-quic is a personal experimental project aimed at implementing the QUIC protocol in Rust while also developing a client tool that offers flexible configuration options for QUIC's underlying features. Along the way, I'll document my thoughts and interesting details from the development process through a series of blog posts:

[Implementing QUIC from Scratch with Rust: A Fresh Start](https://jt26wzz.com/en/posts/0001-implement-quic-in-rust-en/)

[Implementing QUIC from Scratch with Rust: Runtime](https://jt26wzz.com/en/posts/0002-implement-quic-in-rust-en/)

[Implementing QUIC from Scratch with Rust: Trying to analyse and implement QUIC Handshake 😂](https://jt26wzz.com/en/posts/0003-implement-quic-in-rust-en/)

[Implementing QUIC from Scratch with Rust: Implement TLS 1.3 Handshake and QUIC-TLS Key Update](https://jt26wzz.com/en/posts/0004-implement-quic-in-rust-en/)

To be continued

---

**Building and Debugging**

Currently, compilation is tested on Linux and MacOS platforms. Windows platform has not been tested yet, but it should be ok.

Build command:

```bash
cargo build --all-targets
```

Running tests:

1. Start the echo server:
```bash
RUST_LOG=trace ./target/debug/echo-server --listen 127.0.0.1:44437
```

2. Use feather-quic-tool for echo testing:
```bash
RUST_LOG=trace ./target/debug/feather-quic-client-tool \
  --target-address 127.0.0.1:44437 \
  --sni localhost \
  --first-initial-packet-size 1200 \
  --scid dddd1baa12 \
  --alpn echo \
  -e feather-quic-integration-tests/src/tests/test_files/basic_echo_input \
  --ssl-key-log ~/sslkey.log
```

Debugging:

- Use tshark or WireShark to inspect QUIC packets
- View internal feather-quic logs directly

---

Contribution

Contributions are welcome! Feel free to open issues or submit pull requests to improve Feather-QUIC.

---

License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE.md) file for more details.
