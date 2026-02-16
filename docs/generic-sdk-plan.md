# Generic Ably SDK Development Plan Using UTS

> This document is a reusable template for building an Ably SDK in any language,
> driven by the Universal Test Specification (UTS). It was developed alongside
> the Rust SDK implementation — each section captures what needs to be done,
> what materials to reference, and what issues were discovered.

## How to Use This Document

1. Read the phase descriptions to understand the recommended order
2. For each phase, follow the "Steps" to implement in your target language
3. Use the "References" to find the relevant specs and UTS test files
4. Check "Findings" for known issues and pitfalls discovered during development

---

## Phase 0: Foundation & Test Infrastructure

### Goal
Before writing any SDK code, establish the test infrastructure that lets you
run UTS-equivalent tests in your target language.

### Steps

1. **Read UTS mock HTTP spec** (`uts/test/rest/unit/helpers/mock_http.md`).
   Understand the `MockHttpClient` interface: handler-based pattern (`onRequest`
   callback), queue-based pattern (`queue_response`), and request capture for
   assertions.

2. **Read existing test code** to understand current patterns, network-dependent
   tests, and what helpers already exist.

3. **Introduce an HTTP client abstraction** that allows swapping the real HTTP
   client for a mock in tests. The abstraction needs:
   - `execute(request) -> Response` — send a built request
   - `request(method, url) -> RequestBuilder` — start building a request
   - A mechanism for tests to access mock-specific methods on the underlying
     implementation (e.g. language-specific downcasting, generics, or a
     test-only accessor).

   Wrap the production HTTP library in a class/struct implementing this
   abstraction. Refactor the REST client to use the abstraction instead of
   the concrete HTTP library. Keep the abstraction internal — it must not
   become part of the public API.

4. **Implement `MockHttpClient`** (test-only):
   - Handler pattern: provide a callback that receives each request and returns
     a response
   - Queue pattern: pre-queue responses that are returned in FIFO order
   - Request capture: stores every request for later assertions
   - `MockResponse` with constructors for JSON, MessagePack, and empty bodies

5. **Wire default headers into the mock.** Many HTTP libraries merge default
   headers (like `X-Ably-Version`) at send time, not at request-build time.
   Since the mock intercepts the send, it may need to merge default headers
   itself. Provide a way to pass the SDK's default headers to the mock so
   captured requests include them.

6. **Define test conventions:**
   - A helper to create a REST client with a mock HTTP backend
   - A helper to access the mock from a client instance for assertions
   - Test naming convention matching spec points (e.g. `rsc7e_...`)

7. **Verify all existing tests still pass** (both old network-dependent tests
   and new mock-based tests).

### References
- `uts/test/rest/unit/helpers/mock_http.md` — Mock HTTP client specification
- `uts/test/realtime/unit/helpers/mock_websocket.md` — Mock WebSocket specification
- `uts/submodules/ably-common/test-resources/test-app-setup.json` — Sandbox app config

### Findings

- **Default header merge timing:** Some HTTP libraries merge default headers
  internally at send time, not at request-build time. Since the mock intercepts
  the send, captured requests won't contain default headers unless the mock
  explicitly merges them. Solution: extract default headers from client options,
  pass them to the mock, and merge them into captured requests.

- **Test access to mock internals:** When the HTTP client is behind an
  abstraction, tests need to access mock-specific methods (e.g.
  `captured_requests()`). Each language has its own pattern for this —
  downcasting, generics, test-only accessors, etc. Choose the idiom that
  keeps the mock out of the public API.

---

## Phase 1: REST Client Core & Types

### Goal
Implement the REST client constructor, options, and fundamental types.
Align existing code with the UTS tests in `rest/unit/rest_client.md`.

### Steps

1. **RSC5 — Auth attribute:** Verify the REST client exposes an `auth` accessor.
   Typically a trivial assertion if the type system enforces it.

2. **RSC7e — X-Ably-Version header:** Add `X-Ably-Version: 1.2` to default
   headers. Write a mock test that asserts the header is present on requests.

3. **RSC7d — Ably-Agent header:** Add `Ably-Agent: ably-<lang>/<version>` to
   default headers. The version should come from the package metadata
   (e.g. `package.json` version field, build-time constants, etc.). Test that
   the header matches the pattern `ably-<lang>/x.y.z`.

4. **RSC7c — Request IDs:** Implement `addRequestIds` option. When enabled,
   generate a URL-safe random identifier and append it as a `request_id` query
   parameter on every request. The ID should be base64url-encoded (at least
   12 characters). Also test that the same ID is preserved on fallback retries.

5. **RSC8a/b — Protocol selection:** Verify that the default protocol is
   MessagePack (Content-Type: `application/x-msgpack`), and that setting
   `useBinaryProtocol: false` switches to JSON (`application/json`).

6. **RSC8c — Accept header:** Ensure the `Accept` header matches the configured
   protocol. This is typically set as a default header alongside Content-Type.

7. **RSC8d — Mismatched response Content-Type:** Verify the client can decode
   responses in either JSON or MessagePack regardless of which was requested.
   The client should use the response's Content-Type to determine decoding.

8. **RSC8e — Unsupported Content-Type:** Verify error handling:
   - Error status (e.g. 500) + unsupported Content-Type → propagate HTTP status
   - Success status (200) + unsupported Content-Type → error code 40013

9. **RSC13 — Request timeouts:** Implement `httpRequestTimeout` option. Apply
   the timeout at the SDK level (wrapping the HTTP execute call) rather than
   relying solely on the HTTP library's built-in timeout. This ensures
   timeouts work consistently with mock clients in tests. Error code: 50003.

10. **RSC17 — ClientId attribute:** Verify the client ID option is accessible
    on the client object and propagated to the Auth object.

11. **RSC18 — TLS configuration:** Verify:
    - Default is HTTPS
    - `tls: false` uses HTTP
    - Basic auth (API key) is rejected when `tls: false` (error 40103)
    - Token auth over HTTP is allowed

### References
- Spec: `RSC1–RSC18`, `TO1–TO3`, `TI1–TI5`
- UTS: `rest/unit/rest_client.md`, `rest/unit/types/`

### Findings

- **Accept header often missing:** Initial SDK implementations often omit the
  `Accept` header. UTS RSC8c requires it to match the configured protocol.
  Add it as a default header alongside `Content-Type`.

- **Ably-Agent header easily overlooked:** SDKs often implement
  `X-Ably-Version` but forget the `Ably-Agent` header. Both are required.

- **Request IDs may be declared but not wired up:** If the `addRequestIds`
  option exists in the options type but isn't actually used in the request
  path, the UTS test will catch it. The implementation needs to generate a
  random ID and append it as a query parameter before each request is sent.

- **Timeout must be SDK-level, not just HTTP-library-level:** HTTP library
  timeouts only apply to real network requests and won't fire with mock
  clients. The SDK should apply its own timeout (e.g. using the language's
  async timeout mechanism) wrapping the HTTP execute call.

- **Basic auth rejection over non-TLS:** This validation is easy to miss.
  It should be checked at client construction time, before any requests are
  made.

- **Error code for unsupported Content-Type:** The spec requires error code
  40013 (`InvalidMessageDataOrEncoding`) for 2xx responses with unsupported
  Content-Type, not a generic "bad request" error.

---

## Phase 2: Auth

### Goal
Complete authentication: basic auth, token auth, token requests, authorize.

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RSA1–RSA17`
- UTS: `rest/unit/auth/`, `rest/integration/auth.md`

### Findings
<!-- Issues discovered during this phase -->

---

## Phase 3: REST Channels

### Goal
Publishing, history, message encoding/decoding, pagination.

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RSL1–RSL6`, `RSN1–RSN4`, `TM1–TM8`, `TG1–TG7`
- UTS: `rest/unit/channel/`, `rest/unit/encoding/`, `rest/integration/publish.md`

### Findings
<!-- Issues discovered during this phase -->

---

## Phase 4: REST Presence

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RSP1–RSP5`, `TP1–TP5`
- UTS: `rest/unit/presence/`, `rest/integration/presence.md`

---

## Phase 5: Fallback Hosts

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `REC1–REC3`, `RSC15`
- UTS: `rest/unit/fallback.md`

---

## Phase 6: Additional REST Features

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RSC6`, `RSC16`, `RSC19`, `RSC22`, `RSC24`, `RSH1`
- UTS: `rest/unit/request.md`, `rest/unit/stats.md`, `rest/unit/batch_*.md`, `rest/unit/push/`

---

## Phase 7: Realtime Connection

### Goal
WebSocket transport, connection state machine, heartbeats, fallback.

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RTN1–RTN27`, `RTC1–RTC17`
- UTS: `realtime/unit/connection/`, `realtime/unit/client/`

---

## Phase 8: Realtime Channels

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RTL1–RTL32`, `RTS1–RTS5`
- UTS: `realtime/unit/channels/`

---

## Phase 9: Realtime Auth

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RTC8`, `RSA4` (Realtime parts), `RSA8d` (Realtime)
- UTS: `realtime/unit/auth/`

---

## Phase 10: Realtime Presence

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RTP1–RTP19`
- UTS: `realtime/unit/presence/`

---

## Phase 11: Delta/VCDiff

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `PC3`, `VD1–VD2`, `RTL18–RTL21`
- UTS: `realtime/unit/channels/channel_delta_decoding.md`

---

## Phase 12: LiveObjects

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RTO1–RTO19`, `RTLM1–RTLM25`, `RTLC1–RTLC14`, `PO1–PO11`
- UTS: `realtime/unit/objects/`

---

## Phase 13: Mutable Messages & Annotations (Realtime)

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RTL28`, `RTL31–RTL32`, `RTAN1–RTAN5`
- UTS: `realtime/unit/channels/channel_annotations.md`, `realtime/integration/mutable_messages_test.md`

---

## Phase 14: Hardening

### Steps
<!-- To be filled in during implementation -->

### References
- Spec: `RTE1–RTE6`, `RTB1`, `RTN16`, `RTN20`, `RTN27`

---

## Appendix: UTS Findings Log

| Phase | UTS File | Issue | Resolution |
|-------|----------|-------|------------|
| — | — | (populated during development) | — |
