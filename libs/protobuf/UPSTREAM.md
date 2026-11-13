# Protobuf runtime source

This is the protobuf 3.7.2 library from the authenticated Cargo vendor closure.
Its registry archive SHA-256 is
`d65a1d4ddae7d8b5de68153b48f6aa3bba8cb002b243dbdbc55a5afbc98f99f4`.
The original vendor checksum manifest SHA-256 is
`40a1864a08e22ca90889e84f5ab1613f3fac4c3b470ef98c8c7efa8dc80921ee`.
The upstream license, build script, manifest and runtime sources are retained;
the unused regeneration shell script is omitted. Cargo's workspace patch makes
this the runtime for application, generated schemas and build dependencies.

The runtime correction is in `src/coded_input_stream/buf_read_iter.rs`: physical
EOF before an active protobuf length boundary returns `UnexpectedEof`. Reaching
the declared boundary and ordinary unbounded EOF retain their existing behavior.
This covers generated nested messages and packed fields through byte slices,
shared `Bytes`, `Read` and `BufRead` inputs without changing the wire format.
Byte slices and shared `Bytes` start with their actual extent as the input limit;
byte-field allocation checks that limit first. In `coded_input_stream/mod.rs`,
packed-field limits are established before reserving their vectors. These reject
inflated lengths before allocation for finite inputs; unbounded reader resource
limits remain a separate obligation.
The original file SHA-256 is
`2cba31136e56dd63c9a17d1bf4627f430b2ed3ddb35abf4479f57bcb912cdb4e`.
The original `coded_input_stream/mod.rs` SHA-256 is
`9c9eef558aec08a5071303896703aae82a1fa1358d50784e836319e9dcdd2789`.

The generated production-schema regressions live in `libs/protobuf_it`.
Run them through `scripts/smoke-verifier-vm-authority.sh --protobuf-parser-tests`.
Upstream source: <https://github.com/stepancheg/rust-protobuf/tree/v3.7.2/protobuf>.
