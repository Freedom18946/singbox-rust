# Admin API Authentication

## Overview

Admin API supports multiple auth mechanisms:

- JWT bearer tokens
- mTLS client certificates
- HMAC request signing

## Notes

- Avoid exposing the admin API publicly.
- Use rate limiting in production.

## Related

- [API Reference](../README.md)
- [Security Hardening](../../03-operations/security/hardening.md)
