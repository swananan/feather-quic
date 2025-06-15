# feather-quic
用 Rust 实现的轻量级 QUIC 协议栈

[English](./README.en.md)

feather-quic 是一个个人实验性质项目，使用 Rust 实现 QUIC 协议的同时，也实现了一个客户端工具 feather-quic-tool，提供更多 QUIC 协议底层相关的灵活配置，用来对 QUIC 协议进行测试和学习。另外，我会写一系列博客来记录我在开发过程中的想法以及一些有意思的细节：

[用 Rust 从零开始写 QUIC：写在刚开始](https://jt26wzz.com/posts/0001-implement-quic-in-rust/)

[用 Rust 从零开始写 QUIC：Runtime](https://jt26wzz.com/posts/0002-implement-quic-in-rust-runtime/)

[用 Rust 从零开始写 QUIC：尝试深入分析 QUIC 握手😂](https://jt26wzz.com/posts/0003-implement-quic-in-rust/)

[用 Rust 从零开始写 QUIC：实现 TLS 1.3 握手和 QUIC-TLS Key Update](https://jt26wzz.com/posts/0004-implement-quic-in-rust/)

[用 Rust 从零开始写 QUIC：Reliability](https://jt26wzz.com/posts/0005-implement-quic-in-rust/)

[用 Rust 从零开始写 QUIC：实现 QUIC 多路复用流传输和流量控制](https://jt26wzz.com/posts/0006-implement-quic-in-rust/)

[用 Rust 从零开始写 QUIC：实现 QUIC 连接关闭和错误处理](https://jt26wzz.com/posts/0008-implement-quic-in-rust/)

[用 Rust 从零开始写 QUIC： MTU 探测](https://jt26wzz.com/posts/0009-implement-quic-in-rust/)

未完待续

---
**构建和调试**

目前在 Linux 和 Mac 平台都进行过测试，Windows 平台理论上支持。

构建命令:

```bash
cargo build --all-targets
```

运行测试:

1. 启动 echo server:
```bash
RUST_LOG=trace ./target/debug/echo-server --listen 127.0.0.1:44437
```

2. 使用 feather-quic-tool 进行 echo 测试:
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

调试:

- 可以借助 ssl-key-log 生成的对称密钥文件，然后使用 tshark 或 WireShark 查看 QUIC 数据包
- 可以直接查看 feather-quic 内部日志

---

欢迎贡献

欢迎任何形式的贡献！如果有建议或改进，可以通过 Issue 或 Pull Request 提交。

---

许可证

本项目使用 MIT 许可证，详细信息请查看 [LICENSE](./LICENSE.md) 文件。
