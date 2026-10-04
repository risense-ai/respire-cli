//! Local HTTP RPC/MCP transport: loopback peers do not require a token.
use serde_json::json;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

static ACCESS_TOKEN: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

fn set_access_token(t: Option<String>) {
    let _ = ACCESS_TOKEN.set(t);
}

/// Loopback peers need no token. Other peers must authenticate with a header.
fn token_ok(req: &tiny_http::Request) -> bool {
    if req
        .remote_addr()
        .is_some_and(|addr| addr.ip().is_loopback())
    {
        return true;
    }
    let Some(Some(expected)) = ACCESS_TOKEN.get() else {
        return false;
    };
    // Header first
    for h in req.headers() {
        if h.field
            .as_str()
            .as_str()
            .eq_ignore_ascii_case("X-respire-Token")
        {
            if h.value.as_str() == expected.as_str() {
                return true;
            }
        }
        if h.field
            .as_str()
            .as_str()
            .eq_ignore_ascii_case("Authorization")
        {
            let value = h.value.as_str();
            let token = value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "));
            if token == Some(expected.as_str()) {
                return true;
            }
        }
    }
    false
}

fn header_value(req: &tiny_http::Request, name: &str) -> String {
    for header in req.headers() {
        if header.field.as_str().as_str().eq_ignore_ascii_case(name) {
            return header.value.as_str().to_owned();
        }
    }
    String::new()
}

fn mcp_http(
    req: &mut tiny_http::Request,
    method: &tiny_http::Method,
    path: &str,
    bound: SocketAddr,
) -> (u16, &'static str, Vec<u8>) {
    let method_name = match *method {
        tiny_http::Method::Get => "GET",
        tiny_http::Method::Post => "POST",
        _ => "OTHER",
    };
    let mut body = String::new();
    if *method == tiny_http::Method::Post {
        let _ = req.as_reader().read_to_string(&mut body);
    }
    crate::mcp::http_response(crate::mcp::HttpIn {
        method: method_name.to_owned(),
        path: path.to_owned(),
        origin: format!("http://{bound}"),
        accept: header_value(req, "Accept"),
        body,
    })
}

fn handle_request(req: &mut tiny_http::Request, bound: SocketAddr) -> (u16, &'static str, Vec<u8>) {
    let url = req.url().to_owned();
    let method = req.method().to_owned();

    // Only actual loopback peers are exempt; Host and forwarded headers are ignored.
    if !token_ok(req) {
        return (
            401,
            "application/json; charset=utf-8",
            serde_json::json!({"error":"unauthorized: send Authorization: Bearer or X-respire-Token"}).to_string().into_bytes(),
        );
    }

    let host = header_value(req, "Host");
    if !host.eq_ignore_ascii_case(&bound.to_string())
        && !host.eq_ignore_ascii_case(&format!("localhost:{}", bound.port()))
    {
        return (
            403,
            "application/json; charset=utf-8",
            serde_json::json!({"error":"forbidden host"})
                .to_string()
                .into_bytes(),
        );
    }
    let origin = header_value(req, "Origin");
    if !crate::net_rpc::origin_ok(&origin, &format!("http://{bound}")) {
        return (
            403,
            "application/json; charset=utf-8",
            serde_json::json!({"error":"forbidden origin"})
                .to_string()
                .into_bytes(),
        );
    }
    let path = url.split('?').next().unwrap_or(url.as_str());
    if path == "/api/health" && method == tiny_http::Method::Get {
        return (
            200,
            "application/json; charset=utf-8",
            serde_json::to_vec(&crate::rpc::health_body()).unwrap_or_default(),
        );
    }
    if path == "/api/runtime/stop" && method == tiny_http::Method::Post {
        return (
            200,
            "application/json; charset=utf-8",
            serde_json::json!({"ok": true, "server": "respire"})
                .to_string()
                .into_bytes(),
        );
    }
    if path == "/api/rpc" && method == tiny_http::Method::Post {
        let mut body = String::new();
        if req.as_reader().read_to_string(&mut body).is_err() {
            return (
                400,
                "application/json; charset=utf-8",
                serde_json::json!({"error":"request body unreadable"})
                    .to_string()
                    .into_bytes(),
            );
        }
        return match crate::rpc::handle_http_rpc(body.as_bytes()) {
            Ok(response) => (
                200,
                "application/json; charset=utf-8",
                serde_json::to_vec(&response).unwrap_or_default(),
            ),
            Err(error) => (
                400,
                "application/json; charset=utf-8",
                serde_json::json!({"error": error.to_string()})
                    .to_string()
                    .into_bytes(),
            ),
        };
    }
    if path == "/mcp" || path == "/sse" {
        return mcp_http(req, &method, path, bound);
    }

    (
        404,
        "application/json; charset=utf-8",
        json!({"error":"unknown runtime endpoint"})
            .to_string()
            .into_bytes(),
    )
}

pub(crate) struct BoundRuntime {
    pub server: tiny_http::Server,
    pub url: String,
}

pub(crate) fn bind_runtime(port: Option<u16>, host: &str) -> anyhow::Result<BoundRuntime> {
    let actual = port.unwrap_or_else(crate::net_rpc::rpc_port);
    let address = if host == "localhost" {
        let addresses: Vec<SocketAddr> = (host, actual).to_socket_addrs()?.collect();
        anyhow::ensure!(
            !addresses.is_empty() && addresses.iter().all(|address| address.ip().is_loopback()),
            "local runtime requires an exclusively loopback localhost address"
        );
        addresses
            .iter()
            .find(|address| address.is_ipv4())
            .or_else(|| addresses.first())
            .copied()
            .ok_or_else(|| anyhow::anyhow!("localhost has no loopback address"))?
    } else {
        let ip: IpAddr = host.parse().map_err(|_| {
            anyhow::anyhow!("local runtime requires a literal loopback IP or localhost")
        })?;
        anyhow::ensure!(
            ip.is_loopback(),
            "local runtime cannot bind a non-loopback address"
        );
        SocketAddr::new(ip, actual)
    };
    set_access_token(None);
    let server = tiny_http::Server::http(address)
        .map_err(|error| anyhow::anyhow!("failed to bind local runtime at {address}: {error}"))?;
    let url = format!("http://{address}");
    Ok(BoundRuntime { server, url })
}

pub(crate) fn serve_loop(server: tiny_http::Server) -> anyhow::Result<()> {
    let bound = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| anyhow::anyhow!("runtime listener has no IP address"))?;
    for request in server.incoming_requests() {
        std::thread::Builder::new()
            .name("runtime-http".into())
            .spawn(move || {
                if let Err(error) = serve_request(request, bound) {
                    eprintln!("runtime HTTP request failed: {error:#}");
                }
            })?;
    }
    Ok(())
}

fn serve_request(mut request: tiny_http::Request, bound: SocketAddr) -> anyhow::Result<()> {
    let (status, ctype, body) = handle_request(&mut request, bound);
    let stop = status == 200
        && request.method() == &tiny_http::Method::Post
        && request.url().split('?').next() == Some("/api/runtime/stop");
    let mut resp = tiny_http::Response::from_data(body)
        .with_status_code(status)
        .with_header(
            tiny_http::Header::from_bytes(&b"Content-Type"[..], ctype)
                .map_err(|_| anyhow::anyhow!("failed to build Content-Type header"))?,
        );
    if ctype.starts_with("text/event-stream") {
        resp = resp.with_header(
            tiny_http::Header::from_bytes(&b"Cache-Control"[..], "no-cache")
                .map_err(|_| anyhow::anyhow!("failed to build Cache-Control header"))?,
        );
    }
    let result = request.respond(resp);
    if stop {
        crate::rpc::request_drain_exit();
    }
    result?;
    Ok(())
}
