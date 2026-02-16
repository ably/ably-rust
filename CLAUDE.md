# Ably Rust SDK — Development Guide

## Project Overview

This is a full Ably SDK implementation in Rust, being developed using the
**Universal Test Specification (UTS)** as the primary driver for correctness.

Three outputs from this work:
1. **A working Rust SDK** — REST and Realtime
2. **UTS validation** — ambiguities/errors found in UTS tests are corrected
3. **A generic SDK development plan** — reusable template for building any Ably SDK using UTS

## Key Paths

- Source: `src/`
- UTS tests: `../dart-experiments/uts/`
- UTS spec: `../dart-experiments/uts/spec/features.md`
- UTS completion matrix: `../dart-experiments/uts/test/completion-status.md`
- Test fixtures: `submodules/ably-common/test-resources/`
- Development plan: `docs/development-plan.md`
- Generic plan template: `docs/generic-sdk-plan.md`

## Build & Test

```bash
source "$HOME/.cargo/env"     # Ensure cargo is on PATH
cargo check                   # Type check
cargo test                    # Run all tests
cargo test unit_tests         # Run only mock-based unit tests
cargo test <test_name>        # Run specific test
cargo fmt --check             # Format check
cargo clippy -- -D warnings   # Lint
```

## Conventions

- **Async runtime:** tokio
- **HTTP client:** reqwest, abstracted via `HttpClient` trait (`src/http_client.rs`)
- **Serialization:** serde (JSON + MessagePack via rmp-serde)
- **Error handling:** Custom `Error` type with Ably error codes
- **Builder pattern** for options, requests, channels
- **Test approach:** Unit tests (mocked HTTP/WS) + Integration tests (Ably sandbox)
- Tests reference UTS spec items (e.g. RSC7, RTL4) in comments

## Test Architecture

### Mock HTTP (`src/mock_http.rs`)
- `MockHttpClient` implements `HttpClient` trait
- Handler pattern: `MockHttpClient::with_handler(|req| MockResponse::json(200, &body))`
- Queue pattern: `mock.queue_response(MockResponse::json(200, &body))`
- Captured requests: `get_mock(&client).captured_requests()`
- Injected via: `ClientOptions::rest_with_http_client(Box::new(mock))`
- Default headers (X-Ably-Version etc.) are auto-applied by `rest_with_http_client`

### Unit Test Conventions
- Module: `unit_tests` in `src/lib.rs`
- Naming: `rsc7e_x_ably_version_header` (spec item + description)
- Each test has a comment block with spec item and UTS file reference
- Helper: `mock_client(mock)` creates a client with mock backend
- Helper: `get_mock(&client)` gets the MockHttpClient for assertions

### Implemented UTS Tests (rest/unit/rest_client.md)
- RSC5 — Auth attribute
- RSC7c — Request IDs (addRequestIds option)
- RSC7d — Ably-Agent header
- RSC7e — X-Ably-Version header
- RSC8a — Default protocol is MessagePack
- RSC8b — JSON protocol when configured
- RSC8c — Accept and Content-Type headers match protocol
- RSC8d — Mismatched response Content-Type handling
- RSC8e — Unsupported Content-Type error handling
- RSC13 — Request timeouts (via mock delay + SDK-level timeout)
- RSC17 — ClientId attribute
- RSC18 — TLS default, HTTP scheme, basic auth rejection, token auth allowed

### Integration Tests
- Existing tests in `mod tests` in `src/lib.rs`
- Use `TestApp::create()` for sandbox app provisioning
- Require network access to Ably sandbox

## UTS Workflow

### Within a phase

For each feature/spec point in the phase:
1. Read the relevant UTS test spec(s) in `../dart-experiments/uts/test/`
2. Read the corresponding spec items in `../dart-experiments/uts/spec/features.md`
3. Implement the feature in Rust
4. Write Rust tests that correspond to the UTS test cases
5. Note any UTS issues encountered (ambiguities, errors, missing coverage)
6. Record the steps taken in `docs/generic-sdk-plan.md`

### At the end of each phase

1. **Pause for review.** Present a summary of the work done in the phase:
   what was implemented, what tests were added, and any issues encountered.
   Wait for approval before proceeding to the next phase.

2. **Propose UTS changes.** List any suggested changes to UTS:
   - Bug fixes (incorrect assertions, wrong error codes, etc.)
   - Clarity improvements (ambiguous setup, unclear assertions)
   - New test cases that would have caught issues found during implementation
   
   Present these as concrete suggestions with file paths and descriptions.

3. **Create a local commit.** Once the review is complete, commit all changes
   for the phase with a message like: `Phase N: <phase title>`
