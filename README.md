dns-trace-rs
============

[![Software License][ico-license]](LICENSE.md)

This is a bit of practice writing futures in Rust. Given a hostname, `dnstrace` will perform queries starting at the root Internet name servers following the specified authorities until it finds an answer.

Usage
-----

```
USAGE:
    dnstrace <HOST>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <HOST>    The hostname to query
```

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.

[ico-license]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square
