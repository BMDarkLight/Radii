// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 BMDarkLight
//
// This file is part of Radii.
//
// Radii is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for the full text and
// additional terms.

//! Forwarding one HTTP request over one already-established connection.
//!
//! Deliberately knows nothing about how that connection was obtained. A
//! source-routed relay chain and a direct TCP dial are the same thing here,
//! which keeps "how do I reach this backend" in one place and lets this file
//! be tested against a plain socket.
//!
//! Neither body is buffered. Bodies stream client to backend and back, so
//! memory per connection stays constant regardless of upload or download
//! size. Buffering would only be needed to replay a request, and replay is
//! deliberately out of scope — see the retry boundary in
//! `docs/superpowers/specs/2026-09-08-head-reverse-proxy-design.md`.

use anyhow::{Context, Result};
use axum::extract::Request;
use axum::http::header::{HeaderMap, HeaderName};
use axum::response::Response;
use radii_proto::BoxedStream;
use std::time::Duration;

/// Headers that describe a single transport hop and must never be forwarded.
///
/// Beyond this fixed list, every header *named in* a message's own
/// `Connection` header is hop-by-hop for that message too. That is the part
/// implementations most often miss, and forwarding such a header to a
/// backend is request-smuggling surface.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Removes hop-by-hop headers, including those named by `Connection`.
///
/// The `Connection`-named headers are collected *before* anything is
/// removed: dropping `Connection` first would lose the list of what else to
/// drop, silently forwarding exactly the headers this exists to strip.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let mut named: Vec<HeaderName> = Vec::new();
    if let Some(connection) = headers.get("connection") {
        if let Ok(value) = connection.to_str() {
            for token in value.split(',') {
                if let Ok(name) = HeaderName::try_from(token.trim().to_ascii_lowercase().as_str()) {
                    named.push(name);
                }
            }
        }
    }
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

/// Forwards `request` over `stream`, returning the response with its body
/// still streaming.
pub async fn forward(
    stream: BoxedStream,
    request: Request,
    response_timeout: Duration,
) -> Result<Response> {
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .context("http handshake with the backend failed")?;

    // The connection future drives the socket. Dropping it stalls the
    // exchange with no error, so it is spawned rather than awaited; it ends
    // on its own once the response completes.
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::debug!(error = %err, "backend connection closed");
        }
    });

    let (mut parts, body) = request.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    let outbound = hyper::Request::from_parts(parts, body);

    let response = tokio::time::timeout(response_timeout, sender.send_request(outbound))
        .await
        .context("backend did not send response headers in time")?
        .context("backend request failed")?;

    let (mut parts, body) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    Ok(Response::from_parts(parts, axum::body::Body::new(body)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_the_fixed_hop_by_hop_set() {
        let mut headers = HeaderMap::new();
        headers.insert("te", "trailers".parse().unwrap());
        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("x-keep", "yes".parse().unwrap());

        strip_hop_by_hop(&mut headers);

        assert!(headers.get("te").is_none());
        assert!(headers.get("upgrade").is_none());
        assert_eq!(headers.get("x-keep").unwrap(), "yes");
    }

    /// The case implementations usually get wrong, and the reason
    /// `Connection` is read before anything is removed.
    #[test]
    fn strips_headers_named_by_connection_as_well_as_connection_itself() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "X-Hop-One, x-hop-two".parse().unwrap());
        headers.insert("x-hop-one", "a".parse().unwrap());
        headers.insert("x-hop-two", "b".parse().unwrap());
        headers.insert("x-survives", "c".parse().unwrap());

        strip_hop_by_hop(&mut headers);

        assert!(headers.get("connection").is_none());
        assert!(headers.get("x-hop-one").is_none(), "case-insensitive match");
        assert!(headers.get("x-hop-two").is_none());
        assert_eq!(headers.get("x-survives").unwrap(), "c");
    }

    #[test]
    fn tolerates_a_malformed_connection_value() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "  , ,,  ".parse().unwrap());
        headers.insert("x-survives", "c".parse().unwrap());

        strip_hop_by_hop(&mut headers);

        assert!(headers.get("connection").is_none());
        assert_eq!(headers.get("x-survives").unwrap(), "c");
    }
}
