[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=blue)](https://pkg.go.dev/github.com/mongodb-forks/digest)
![CI](https://github.com/mongodb-forks/digest/workflows/CI/badge.svg)
# Golang HTTP Digest Authentication

## Overview

This is a fork of the (unmaintained) code.google.com/p/mlab-ns2/gae/ns/digest package.
There's a descriptor leak in the original package, so this fork was created to patch
the leak.

### Update 2020

This is a fork of the now unmaintained fork of [digest](https://github.com/bobziuchkovski/digest).
This implementation now supports the SHA-256 algorithm which was added as part of [rfc 7616](https://tools.ietf.org/html/rfc7616).

## Usage

See the [godocs](https://godoc.org/github.com/bobziuchkovski/digest) for details.

## Contributing

**Contributions are welcome!**

The code is linted with [golangci-lint](https://golangci-lint.run/).  This library also defines *git hooks* that format and lint the code.

Before submitting a PR, please run `make setup link-git-hooks` to set up your local development environment.

## Original Authors

- Bipasa Chattopadhyay <bipasa@cs.unc.edu>
- Eric Gavaletz <gavaletz@gmail.com>
- Seon-Wook Park <seon.wook@swook.net>
- Bob Ziuchkovski (@bobziuchkovski)

## License

Apache 2.0
