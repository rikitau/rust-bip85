# BIP-85 implementation in Rust

[BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki) - deterministic entropy from bip32 keychains.

Derives entropy from the extended private key according to
[BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki).

Try it [online](https://rikitau.github.io/wasm-bip85/) with WASM magic!

# Examples

There are a few [examples](https://github.com/rikitau/rust-bip85/tree/master/examples)
in the repository.

Running examples:

```sh
cargo run --example simple
```

```sh
cargo run --example mnemonic --features japanese
```

# Optional features

By default the library can derive entropy in any format specified by the standard except
mnemonics. To use mnemonics enable feature "mnemonic".

All bip-39 languages except english are also optional, so if you plan generating mnemonics in
japanese enable feature "japanese", and so on.
