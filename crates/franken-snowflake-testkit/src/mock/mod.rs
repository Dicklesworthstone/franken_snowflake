//! The deterministic, no-account mock SQL API.
//!
//! This is the no-socket substrate the statement-lifecycle (`ofl`), the
//! VirtualTcp/DPOR race suite (`fsnow-native-snowflake-connector-w0i.4`), and the
//! end-to-end harness (`...w0i.12`) drive against — **without a live Snowflake
//! account and without a network**. Three cooperating pieces:
//!
//! - [`http`] — transport-neutral [`http::MockHttpRequest`] /
//!   [`http::MockHttpResponse`] plus [`http::MockHttpResponse::to_wire`], which
//!   renders a response as raw HTTP/1.1 bytes (CRLF-framed). Those bytes are the
//!   **golden protocol packets** a [`http::MockHttpResponse`] feeds to an
//!   `Http1Client` codec over a `VirtualTcpStream` pair.
//! - [`server`] — [`server::MockSqlApi`], a stateful submit → poll(202)×N → 200
//!   (or 408/422) → cancel state machine. It is the integration-lane logic a
//!   `fastapi_rust` handler will call, and it records every request (with the
//!   `Authorization` header **pre-redacted**) for auth-leak inspection.
//! - [`scenarios`] — the canned response catalog. The 200/202/408/422 bodies are
//!   the kx6 protocol goldens embedded verbatim (single source of truth); the
//!   429 backoff body and the gzip partition packet are testkit-owned fixtures.
//!
//! Determinism: response bytes are pure functions of the fixtures; the gzip
//! partition fixture is built with `gzip -n` (no embedded timestamp). Pair this
//! with [`crate::harness::clock`] for reproducible poll/backoff timing and
//! [`crate::harness::golden`] for byte-exact packet/body assertions.

use std::collections::VecDeque;

pub mod http;
pub mod scenarios;
pub mod server;

use http::MockHttpResponse;

/// A FIFO of canned responses for the primary deterministic lane: a test driver
/// pulls them in order to script a single connection's reply sequence (e.g. the
/// `202 → 202 → 200` poll progression), independent of any socket.
#[derive(Clone, Debug, Default)]
pub struct ScriptedResponder {
    queue: VecDeque<MockHttpResponse>,
}

impl ScriptedResponder {
    /// A responder that will hand back `responses` in order.
    #[must_use]
    pub fn new(responses: Vec<MockHttpResponse>) -> Self {
        Self {
            queue: responses.into(),
        }
    }

    /// Queue another response after the current ones.
    pub fn push(&mut self, response: MockHttpResponse) -> &mut Self {
        self.queue.push_back(response);
        self
    }

    /// The next scripted response, or `None` once the script is exhausted.
    pub fn next_response(&mut self) -> Option<MockHttpResponse> {
        self.queue.pop_front()
    }

    /// The next scripted response rendered as raw HTTP/1.1 wire bytes.
    pub fn next_wire(&mut self) -> Option<Vec<u8>> {
        self.queue.pop_front().map(|response| response.to_wire())
    }

    /// Remaining scripted responses.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.queue.len()
    }

    /// Whether the script is exhausted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripted_responder_yields_in_order_then_empties() {
        let mut responder = ScriptedResponder::new(scenarios::poll_progression());
        // 202 running, 202 running, 200 completed.
        assert_eq!(responder.remaining(), 3);
        assert_eq!(responder.next_response().map(|r| r.status), Some(202));
        assert_eq!(responder.next_response().map(|r| r.status), Some(202));
        let completed = responder.next_wire();
        assert!(completed.is_some());
        assert!(responder.is_empty());
        assert_eq!(responder.next_response().map(|r| r.status), None);
    }
}
