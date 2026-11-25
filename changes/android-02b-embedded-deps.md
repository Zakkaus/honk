Changed

- DNS-over-HTTP/3 upstreams (`h3://`) need the new `doh3` Cargo feature, which `daemon` enables. A library build without it compiles neither `h3` nor `h3-quinn`, and such an upstream fails to build its transport.
