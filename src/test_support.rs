//! Shared unit-test helpers: mock-backed REST clients. Previously pasted
//! into every tests_*_unit_* file; one definition lives here.

use crate::mock_http::MockHttpClient;
use crate::options::ClientOptions;

/// Helper to create a Rest client with a mock HTTP backend.
pub(crate) fn mock_client(mock: MockHttpClient) -> crate::Rest {
    ClientOptions::new("appId.keyId:keySecret")
        .rest_with_mock(mock)
        .unwrap()
}

/// Helper to get captured requests from a client with a mock backend.
pub(crate) fn get_mock(client: &crate::Rest) -> &MockHttpClient {
    client.inner.mock_handle.as_ref().unwrap()
}

/// Create a mock REST client with JSON format (for tests that inspect request body).
pub(crate) fn mock_client_json(mock: MockHttpClient) -> crate::Rest {
    ClientOptions::new("appId.keyId:keySecret")
        .use_binary_protocol(false)
        .rest_with_mock(mock)
        .unwrap()
}
