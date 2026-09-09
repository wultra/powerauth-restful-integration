# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add request encryption annotation for activation rename endpoint and handle validation exception [(#735)](https://github.com/wultra/powerauth-restful-integration/issues/735)

## [2.2.0] - 2026-07-20

### Added

- Document error codes for mobile SDK [(#712)](https://github.com/wultra/powerauth-restful-integration/issues/712)
- Return unblock timestamp for activations [(#715)](https://github.com/wultra/powerauth-restful-integration/issues/715)
- Added secure configuration endpoints for the mobile SDK [(#714)](https://github.com/wultra/powerauth-restful-integration/issues/714)

### Changed

- Allow 1FA activation remove in v3 endpoint [(#684)](https://github.com/wultra/powerauth-restful-integration/issues/684)
- Migrate to Spring Boot 4 and Jackson 3 [(#705)](https://github.com/wultra/powerauth-restful-integration/issues/705)
- Update Spring Boot version [(#720)](https://github.com/wultra/powerauth-restful-integration/issues/720)

### Fixed

- Authentication token status should match authentication context [(#707)](https://github.com/wultra/powerauth-restful-integration/issues/707)
- Register Lombok annotation processor [(#709)](https://github.com/wultra/powerauth-restful-integration/issues/709)

[unreleased]: https://github.com/wultra/powerauth-restful-integration/compare/2.2.0...HEAD
[2.2.0]: https://github.com/wultra/powerauth-restful-integration/compare/2.1.1...2.2.0
