# SigmaOS firewall

This crate is currently a `no_std` identity scaffold. Its library constructs a
`Component` named `SigmaOS-firewall`; it does not filter packets, manage
firewall rules, or enforce a network security policy. The inline unit test
checks only the fixed name.

## Build

```sh
cargo check --lib
```

## License

Apache-2.0. See [`Cargo.toml`](Cargo.toml).

