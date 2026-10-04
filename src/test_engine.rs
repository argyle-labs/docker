//! A fake Docker Engine on a Unix socket that answers by route, for tests of
//! tools that read and remove engine resources.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bollard::Docker;

/// One canned answer: `method` plus a path suffix (the `/v1.xx` prefix is
/// ignored), optionally narrowed to requests whose percent-decoded query
/// contains `query`, mapped to a status and JSON body. The first match wins.
#[derive(Clone)]
pub struct Route {
    pub method: &'static str,
    pub path: String,
    pub query: Option<String>,
    pub status: u16,
    pub body: String,
}

impl Route {
    pub fn new(
        method: &'static str,
        path: impl Into<String>,
        status: u16,
        body: impl Into<String>,
    ) -> Self {
        Self {
            method,
            path: path.into(),
            query: None,
            status,
            body: body.into(),
        }
    }

    pub fn when_query(mut self, contains: impl Into<String>) -> Self {
        self.query = Some(contains.into());
        self
    }
}

/// Percent-decode a request target (`+` stays as is; bollard encodes spaces
/// as `%20`).
pub fn decode(target: &str) -> String {
    let bytes = target.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(b) = u8::from_str_radix(&target[i + 1..i + 3], 16)
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub struct FakeEngine {
    _dir: tempfile::TempDir,
    path: PathBuf,
    seen: Arc<Mutex<Vec<String>>>,
    bodies: Arc<Mutex<Vec<(String, String)>>>,
}

impl FakeEngine {
    /// Unmatched requests get a 404 with docker's error envelope.
    pub fn routed(routes: Vec<Route>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("docker.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let body_log = bodies.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }
                let request_line = request_line.trim_end().to_string();
                log.lock().expect("lock").push(request_line.clone());
                let mut header = String::new();
                let mut length = 0usize;
                while reader
                    .read_line(&mut header)
                    .map(|n| n > 2)
                    .unwrap_or(false)
                {
                    if let Some((k, v)) = header.split_once(':')
                        && k.eq_ignore_ascii_case("content-length")
                    {
                        length = v.trim().parse().unwrap_or(0);
                    }
                    header.clear();
                }
                if length > 0 {
                    let mut buf = vec![0u8; length];
                    if std::io::Read::read_exact(&mut reader, &mut buf).is_ok() {
                        body_log.lock().expect("lock").push((
                            request_line.clone(),
                            String::from_utf8_lossy(&buf).into_owned(),
                        ));
                    }
                }
                let mut parts = request_line.split(' ');
                let method = parts.next().unwrap_or_default();
                let target = parts.next().unwrap_or_default();
                let path = target.split('?').next().unwrap_or_default();
                let query = decode(target.split_once('?').map(|(_, q)| q).unwrap_or_default());
                let (status, body) = routes
                    .iter()
                    .find(|r| {
                        r.method == method
                            && path.ends_with(&r.path)
                            && r.query.as_ref().is_none_or(|q| query.contains(q.as_str()))
                    })
                    .map(|r| (r.status, r.body.clone()))
                    .unwrap_or((404, r#"{"message":"no such route"}"#.to_string()));
                let response = format!(
                    "HTTP/1.1 {status} Fake\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                if stream.write_all(response.as_bytes()).is_err() {
                    continue;
                }
            }
        });
        Self {
            _dir: dir,
            path,
            seen,
            bodies,
        }
    }

    pub fn client(&self) -> Docker {
        Docker::connect_with_unix(
            self.path.to_str().expect("utf8 path"),
            5,
            bollard::API_DEFAULT_VERSION,
        )
        .expect("client")
    }

    /// Request lines seen so far, e.g. `DELETE /v1.52/volumes/abc HTTP/1.1`.
    pub fn requests(&self) -> Vec<String> {
        self.seen.lock().expect("lock").clone()
    }

    /// Bodies of requests whose path ends with `path`, in order.
    pub fn bodies(&self, path: &str) -> Vec<String> {
        self.bodies
            .lock()
            .expect("lock")
            .iter()
            .filter(|(line, _)| {
                line.split(' ')
                    .nth(1)
                    .and_then(|t| t.split('?').next())
                    .is_some_and(|p| p.ends_with(path))
            })
            .map(|(_, b)| b.clone())
            .collect()
    }

    /// Percent-decoded request targets (path and query) with the given method.
    pub fn targets(&self, method: &str) -> Vec<String> {
        self.requests()
            .iter()
            .filter_map(|l| {
                let mut p = l.split(' ');
                (p.next() == Some(method)).then(|| decode(p.next().unwrap_or_default()))
            })
            .collect()
    }

    /// The request lines with the given method, path only.
    pub fn paths(&self, method: &str) -> Vec<String> {
        self.requests()
            .iter()
            .filter_map(|l| {
                let mut p = l.split(' ');
                (p.next() == Some(method)).then(|| {
                    p.next()
                        .unwrap_or_default()
                        .split('?')
                        .next()
                        .unwrap_or_default()
                        .to_string()
                })
            })
            .collect()
    }
}
