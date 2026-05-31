# quinn-deferred-config


ClientHello-based deferred `rustls::ServerConfig` selection for
[Quinn](https://github.com/quinn-rs/quinn).


This is a prototype/compatibility adapter for Quinn 0.11. It is useful for
experiments and legacy integration, but a Quinn-native staged accept API would
be cleaner because Quinn could keep and transfer the handshake state directly.

This crate lets a Quinn server accept connections on one UDP endpoint and
choose the final TLS server configuration after seeing the client's TLS
`ClientHello`. The selector can inspect the requested SNI and ALPN values,
then return the `rustls::ServerConfig` that should handle that connection.

The main use case is a multi-tenant QUIC server where different hostnames or
protocols need different TLS configuration, certificate chains, ALPN policy, or
client-auth policy, while still sharing a single socket.

## Why

Quinn normally receives a crypto `ServerConfig` before a connection handshake
starts. That works well for a single TLS configuration, but it is awkward when
the server needs to choose between complete `rustls::ServerConfig` values based
on data that only appears in the client's `ClientHello`.

`quinn-deferred-config` provides a small adapter:

1. Quinn starts the connection with a default QUIC-compatible rustls config.
2. The adapter buffers incoming CRYPTO handshake bytes.
3. Once a full `ClientHello` is available, it extracts SNI and ALPN.
4. Your selector callback chooses the final `rustls::ServerConfig`.
5. The adapter creates a real Quinn/rustls session from that config and replays
   the buffered handshake bytes into it.

No Quinn fork and no rustls patch are required.


## Usage

```rust
use std::sync::Arc;

use quinn::ServerConfig;
use quinn_deferred_config::{ClientHelloView, DeferredServerConfig, Selector};

let default_config: Arc<rustls::ServerConfig> = build_default_rustls_config();
let host_a_config: Arc<rustls::ServerConfig> = build_host_a_rustls_config();
let host_b_config: Arc<rustls::ServerConfig> = build_host_b_rustls_config();

let fallback = default_config.clone();
let selector: Selector = Arc::new(move |hello: &ClientHelloView<'_>| {
    match hello.server_name {
        Some("host-a.example") => host_a_config.clone(),
        Some("host-b.example") => host_b_config.clone(),
        _ => fallback.clone(),
    }
});

let deferred = DeferredServerConfig::new(default_config, selector)?;
let quinn_server_config = ServerConfig::with_crypto(Arc::new(deferred));
```

For a runnable end-to-end demo:

```sh
cargo run --example multi_tenant
```

The example starts one Quinn server endpoint and connects twice, once with
`host-a.test` and once with `host-b.test`. Each connection receives the
certificate selected for its requested SNI.

## API

The selector receives a minimal borrowed view of the parsed `ClientHello`:

```rust
pub struct ClientHelloView<'a> {
    pub server_name: Option<&'a str>,
    pub alpn: &'a [&'a [u8]],
    pub raw: &'a [u8],
}
```

Return the `Arc<rustls::ServerConfig>` that should serve this connection:

```rust
pub type Selector =
    Arc<dyn Fn(&ClientHelloView<'_>) -> Arc<rustls::ServerConfig> + Send + Sync + 'static>;
```


## Status

This is a prototype targeting Quinn 0.11 and rustls 0.23.

Current behavior:

- Extracts SNI and ALPN from the first TLS `ClientHello`.
- Selects one complete `rustls::ServerConfig` per connection.
- Buffers only until the full `ClientHello` is available.
- Delegates to Quinn's existing rustls integration after selection.

Current limitations:

- This is not a general-purpose TLS parser.
- The selector is synchronous.
- The selected config must be QUIC-compatible and have a TLS 1.3 cipher suite
  supported by Quinn/rustls.
- The default config is still required so Quinn can provide initial keys and
  retry handling before selection completes.

## Testing

```sh
cargo test
```

The integration test verifies that SNI steers the server to the matching
per-host config.
