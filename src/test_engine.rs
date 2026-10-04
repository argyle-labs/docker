//! A fake Docker Engine on a Unix socket that answers by route, for tests of
//! tools that read and remove engine resources.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bollard::Docker;

/// One canned answer: `method` plus a path suffix (the `/v1.xx` prefix and
/// query string are ignored) mapped to a status and JSON body.
#[derive(Clone)]
pub struct Route {
    pub method: &'static str,
    pub path: String,
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
            status,
            body: body.into(),
        }
    }
}

pub struct FakeEngine {
    _dir: tempfile::TempDir,
    path: PathBuf,
    seen: Arc<Mutex<Vec<String>>>,
}

impl FakeEngine {
    /// Unmatched requests get a 404 with docker's error envelope.
    pub fn routed(routes: Vec<Route>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("docker.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
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
                while reader
                    .read_line(&mut header)
                    .map(|n| n > 2)
                    .unwrap_or(false)
                {
                    header.clear();
                }
                let mut parts = request_line.split(' ');
                let method = parts.next().unwrap_or_default();
                let target = parts.next().unwrap_or_default();
                let path = target.split('?').next().unwrap_or_default();
                let (status, body) = routes
                    .iter()
                    .find(|r| r.method == method && path.ends_with(&r.path))
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
