# Troubleshooting

## Client Does Not Connect

The client now waits for an authenticated `HELLO_ACK` from the server for every KCP session. If the server
is down, UDP is blocked, or the key is wrong, the session fails instead of being marked connected.

Check:

- Server is listening on the expected UDP host and port.
- Client `-s` and `-p` match the server address and port.
- Both sides use the same key and the key is at least 16 characters.
- Firewalls allow UDP in both directions.

## SOCKS5 Works for HTTP but Not QUIC

This proxy supports SOCKS5 CONNECT for TCP only. It does not support `UDP ASSOCIATE`, QUIC/HTTP3, or UDP
DNS. Disable QUIC/HTTP3 in clients that otherwise prefer UDP.

## Domain Connect Fails Intermittently

The server resolves all A/AAAA results and uses Asio `async_connect` over the endpoint sequence. A failure
should only be returned after all resolved endpoints fail or the connect timeout fires.

Use `-L DEBUG` to inspect endpoint-level diagnostics when adding deeper logging.

## Log Volume

`INFO` is intended for lifecycle events: server/client start, session creation/close, SOCKS5 target,
connect success/failure, and fatal errors. Packet-level UDP/KCP/TCP forwarding details are logged at
`DEBUG`.

Do not log keys or payload bytes.

## Common Failure Stages

- `AUTH_FAILED`: first encrypted packet could not be authenticated.
- `DECRYPT_FAILED`: packet decryption or tag verification failed.
- `REPLAY_DETECTED`: replay window rejected a packet.
- `SOCKS5_PARSE_FAILED`: SOCKS5 request was invalid or too large.
- `SOCKS5_UNSUPPORTED_COMMAND`: command was `BIND`, `UDP ASSOCIATE`, or unknown.
- `DNS_RESOLVE_FAILED`: domain resolution failed.
- `TCP_CONNECT_FAILED`: all outbound TCP connect attempts failed.
- `TCP_READ_FAILED` / `TCP_WRITE_FAILED`: remote TCP stream failed during forwarding.
- `UDP_SEND_FAILED`: UDP send failed.
- `SESSION_TIMEOUT`: session idle/KCP timeout cleanup.
