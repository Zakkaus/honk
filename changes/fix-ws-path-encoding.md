Fixed

- WebSocket and gRPC nodes whose path or service name contains a space or non-ASCII text now connect instead of failing with "invalid uri character" ([#378](https://github.com/daeuniverse/honk/issues/378)).
