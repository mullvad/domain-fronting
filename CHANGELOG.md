# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Change proxy address field to support more than 1 address.
- Use the Happy Eyeballs algorithm in `connect_https2`, `connect_https1_1`, and `connect_http1_1`.
- Export `happy_eyeballs::connect` helper function.
- Publicly re-export crates used in public API.


## [0.2.0] - 2026-09-24
- Reachitecture protocol to use long-polling for efficiency.
- Add HTTP/2 support to the client.


## [0.1.0] - 2026-04-29
- Add domain fronting server and client library
