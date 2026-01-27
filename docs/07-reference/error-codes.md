# Error Codes

## Overview

Error codes appear in CLI output and Admin API responses.

## Where to look

- CLI exit codes: `docs/02-cli-reference/exit-codes.md`
- Admin API errors: `docs/05-api-reference/README.md`

## Notes

- CLI uses standard exit codes for validation and runtime errors.
- Admin API uses a JSON envelope with `kind` and `msg` fields.
