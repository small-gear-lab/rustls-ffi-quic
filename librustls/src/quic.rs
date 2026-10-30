//! A C API over `rustls::quic`: a QUIC client handshake driven by the caller, who moves the
//! handshake bytes between this connection and the QUIC packets of its own transport.
//!
//! Experimental. The functions are named as upstream would name them; the downstream renaming
//! of the exported symbols is applied on top by a script.

use std::ffi::c_char;
use std::sync::{Arc, Mutex};

use libc::size_t;
use rustls::{ClientConfig, KeyLog};
use rustls::pki_types::ServerName;
use rustls::quic::{ClientConnection, KeyChange, Version};

use crate::client::rustls_client_config;
use crate::error::{map_error, rustls_result};
use crate::ffi::{
    Castable, OwnershipBox, free_box, set_boxed_mut_ptr, try_clone_arc, try_cstr,
    try_mut_from_ptr, try_mut_from_ptr_ptr, try_slice, try_slice_mut,
};
use crate::panic::ffi_panic_boundary;
use crate::rslice::rustls_slice_bytes;

/// The QUIC version a connection runs, which governs version-specific behaviour of TLS.
pub const RUSTLS_QUIC_VERSION_V1: u32 = 1;
pub const RUSTLS_QUIC_VERSION_V2: u32 = 2;
pub const RUSTLS_QUIC_VERSION_V1_DRAFT: u32 = 0x1d;

/// Which keys `rustlsq_quic_connection_write_hs` made available after the bytes it wrote.
pub const RUSTLS_QUIC_KEYS_NONE: u32 = 0;
pub const RUSTLS_QUIC_KEYS_HANDSHAKE: u32 = 1;
pub const RUSTLS_QUIC_KEYS_ONE_RTT: u32 = 2;

/// Which traffic secret `rustlsq_quic_connection_secret` returns.
pub const RUSTLS_QUIC_SECRET_CLIENT_EARLY: u32 = 0;
pub const RUSTLS_QUIC_SECRET_CLIENT_HANDSHAKE: u32 = 1;
pub const RUSTLS_QUIC_SECRET_SERVER_HANDSHAKE: u32 = 2;
pub const RUSTLS_QUIC_SECRET_CLIENT_APPLICATION: u32 = 3;
pub const RUSTLS_QUIC_SECRET_SERVER_APPLICATION: u32 = 4;

const SECRET_LABELS: [&str; 5] = [
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
];

type SecretStore = Arc<Mutex<[Option<Vec<u8>>; 5]>>;

/// Keeps the traffic secrets of one connection, and passes every line on to the key log that
/// the config had. Rustls only shows the secrets through its key log; a QUIC stack needs them
/// to derive its own packet keys.
#[derive(Debug)]
struct SecretTap {
    store: SecretStore,
    next: Arc<dyn KeyLog>,
}

impl KeyLog for SecretTap {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        if let Some(i) = SECRET_LABELS.iter().position(|l| *l == label) {
            self.store.lock().unwrap()[i] = Some(secret.to_vec());
        }
        self.next.log(label, client_random, secret);
    }

    fn will_log(&self, _label: &str) -> bool {
        true
    }
}

/// A QUIC client connection, the TLS side of it only.
///
/// Under the hood, this object corresponds to a `rustls::quic::ClientConnection`.
pub struct rustls_quic_connection {
    _private: [u8; 0],
}

pub struct QuicClient {
    conn: ClientConnection,
    secrets: SecretStore,
    pending: Option<KeyChange>,
}

impl Castable for rustls_quic_connection {
    type Ownership = OwnershipBox;
    type RustType = QuicClient;
}

impl rustls_quic_connection {
    /// Create a QUIC client connection. `params` is the TLS-encoded QUIC transport parameters
    /// to send. `alpn_protocols` overrides the ALPN of the config as
    /// `rustlsq_client_connection_new_alpn` does. The config must allow TLS 1.3.
    #[no_mangle]
    pub extern "C" fn rustlsq_quic_client_connection_new(
        config: *const rustls_client_config,
        quic_version: u32,
        server_name: *const c_char,
        alpn_protocols: *const rustls_slice_bytes,
        alpn_protocols_len: size_t,
        params: *const u8,
        params_len: size_t,
        conn_out: *mut *mut rustls_quic_connection,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let version = match quic_version {
                RUSTLS_QUIC_VERSION_V1 => Version::V1,
                RUSTLS_QUIC_VERSION_V2 => Version::V2,
                RUSTLS_QUIC_VERSION_V1_DRAFT => Version::V1Draft,
                _ => return rustls_result::InvalidParameter,
            };
            let raw_protocols = try_slice!(alpn_protocols, alpn_protocols_len);
            let mut alpn = Vec::with_capacity(raw_protocols.len());
            for p in raw_protocols {
                alpn.push(try_slice!(p.data, p.len).to_vec());
            }
            let params = try_slice!(params, params_len).to_vec();
            let Ok(server_name) = try_cstr!(server_name).to_str() else {
                return rustls_result::InvalidDnsNameError;
            };
            let Ok(server_name) = ServerName::try_from(server_name) else {
                return rustls_result::InvalidDnsNameError;
            };
            // a copy of the config whose key log also keeps this connection's secrets
            let shared: Arc<ClientConfig> = try_clone_arc!(config);
            let mut config = ClientConfig::clone(&shared);
            let secrets = SecretStore::default();
            config.key_log = Arc::new(SecretTap { store: secrets.clone(), next: config.key_log.clone() });
            let conn = match ClientConnection::new_with_alpn(
                Arc::new(config),
                version,
                server_name.to_owned(),
                params,
                alpn,
            ) {
                Ok(c) => c,
                Err(e) => return map_error(e),
            };
            set_boxed_mut_ptr(
                try_mut_from_ptr_ptr!(conn_out),
                QuicClient { conn, secrets, pending: None },
            );
            rustls_result::Ok
        }
    }

    /// Give the connection the handshake bytes that arrived in CRYPTO frames, in order, at the
    /// encryption level they were received at.
    #[no_mangle]
    pub extern "C" fn rustlsq_quic_connection_read_hs(
        conn: *mut rustls_quic_connection,
        data: *const u8,
        len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let conn = try_mut_from_ptr!(conn);
            match conn.conn.read_hs(try_slice!(data, len)) {
                Ok(()) => rustls_result::Ok,
                Err(e) => map_error(e),
            }
        }
    }

    /// Take the handshake bytes to send, at the current encryption level. After them, the
    /// connection may have new keys: `*keys_out` says which.
    ///
    /// Writes at most `cap` bytes to `out` and the count to `*len_out`. If there is more, call
    /// again with `*keys_out` still NONE; the keys are reported by the call that writes the
    /// last bytes of the level.
    #[no_mangle]
    pub extern "C" fn rustlsq_quic_connection_write_hs(
        conn: *mut rustls_quic_connection,
        out: *mut u8,
        cap: size_t,
        len_out: *mut size_t,
        keys_out: *mut u32,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let conn = try_mut_from_ptr!(conn);
            let out = try_slice_mut!(out, cap);
            let mut buf = Vec::new();
            if conn.pending.is_none() {
                conn.pending = conn.conn.write_hs(&mut buf);
            }
            if buf.len() > out.len() {
                return rustls_result::InsufficientSize;
            }
            out[..buf.len()].copy_from_slice(&buf);
            let keys = match &conn.pending {
                None => RUSTLS_QUIC_KEYS_NONE,
                Some(KeyChange::Handshake { .. }) => RUSTLS_QUIC_KEYS_HANDSHAKE,
                Some(KeyChange::OneRtt { .. }) => RUSTLS_QUIC_KEYS_ONE_RTT,
            };
            unsafe {
                *len_out = buf.len();
                *keys_out = keys;
            }
            conn.pending = None;
            rustls_result::Ok
        }
    }

    /// Whether the handshake is still going on.
    #[no_mangle]
    pub extern "C" fn rustlsq_quic_connection_is_handshaking(
        conn: *const rustls_quic_connection,
    ) -> bool {
        ffi_panic_boundary! {
            crate::ffi::try_ref_from_ptr!(conn).conn.is_handshaking()
        }
    }

    /// The TLS alert to send when the handshake failed. Returns false when there is none.
    #[no_mangle]
    pub extern "C" fn rustlsq_quic_connection_alert(
        conn: *const rustls_quic_connection,
        alert_out: *mut u8,
    ) -> bool {
        ffi_panic_boundary! {
            match crate::ffi::try_ref_from_ptr!(conn).conn.alert() {
                Some(a) => {
                    unsafe { *alert_out = u8::from(a) };
                    true
                }
                None => false,
            }
        }
    }

    /// Copy a traffic secret (`RUSTLS_QUIC_SECRET_*`) to `out`, at most `cap` bytes, and its length
    /// to `*len_out`. Returns false while the secret does not exist yet. Each secret exists from the
    /// moment the handshake bytes that give it have been read (`read_hs`), which is before
    /// `write_hs` reports the keys.
    #[no_mangle]
    pub extern "C" fn rustlsq_quic_connection_secret(
        conn: *const rustls_quic_connection,
        kind: u32,
        out: *mut u8,
        cap: size_t,
        len_out: *mut size_t,
    ) -> bool {
        ffi_panic_boundary! {
            let conn = crate::ffi::try_ref_from_ptr!(conn);
            let out = try_slice_mut!(out, cap);
            let store = conn.secrets.lock().unwrap();
            let Some(Some(s)) = store.get(kind as usize) else {
                return false;
            };
            if s.len() > out.len() {
                return false;
            }
            out[..s.len()].copy_from_slice(s);
            unsafe { *len_out = s.len() };
            true
        }
    }

    /// The IANA number of the negotiated TLS 1.3 cipher suite (0x1301, 0x1302 or 0x1303), or 0
    /// while none is negotiated yet.
    #[no_mangle]
    pub extern "C" fn rustlsq_quic_connection_cipher_suite(
        conn: *const rustls_quic_connection,
    ) -> u16 {
        ffi_panic_boundary! {
            match crate::ffi::try_ref_from_ptr!(conn).conn.negotiated_cipher_suite() {
                Some(s) => u16::from(s.suite()),
                None => 0,
            }
        }
    }

    /// The QUIC transport parameters of the peer, once they have arrived. The pointer is valid
    /// until the connection is changed or freed.
    #[no_mangle]
    pub extern "C" fn rustlsq_quic_connection_peer_transport_parameters(
        conn: *const rustls_quic_connection,
        out: *mut *const u8,
        len_out: *mut size_t,
    ) -> bool {
        ffi_panic_boundary! {
            match crate::ffi::try_ref_from_ptr!(conn).conn.quic_transport_parameters() {
                Some(p) => {
                    unsafe {
                        *out = p.as_ptr();
                        *len_out = p.len();
                    }
                    true
                }
                None => false,
            }
        }
    }

    /// Free a `rustls_quic_connection`. Calling with NULL is fine.
    #[no_mangle]
    pub extern "C" fn rustlsq_quic_connection_free(conn: *mut rustls_quic_connection) {
        ffi_panic_boundary! {
            free_box(conn);
        }
    }
}

#[cfg(all(test, feature = "aws-lc-rs"))]
mod tests {
    use std::ffi::CString;
    use std::ptr::{null, null_mut};
    use std::sync::{Arc, Mutex};

    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::quic::ServerConnection;
    use rustls::{KeyLog, RootCertStore, ServerConfig};

    use super::*;
    use crate::ffi::to_arc_const_ptr;

    #[derive(Debug)]
    struct Recorder(Arc<Mutex<Vec<String>>>);

    impl KeyLog for Recorder {
        fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
            self.0
                .lock()
                .unwrap()
                .push(format!("keylog {label} ({} bytes)", secret.len()));
        }
    }

    fn dir(name: &str) -> String {
        format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn handshake_and_secret_timing() {
        let events = Arc::new(Mutex::new(Vec::<String>::new()));

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = RootCertStore::empty();
        for c in CertificateDer::pem_file_iter(dir("minica.pem")).unwrap() {
            roots.add(c.unwrap()).unwrap();
        }
        let mut client_config = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.key_log = Arc::new(Recorder(events.clone()));
        let config: *const rustls_client_config = to_arc_const_ptr(client_config);

        let certs = CertificateDer::pem_file_iter(dir("localhost/cert.pem"))
            .unwrap()
            .map(|c| c.unwrap())
            .collect::<Vec<_>>();
        let key = PrivateKeyDer::from_pem_file(dir("localhost/key.pem")).unwrap();
        let mut server_config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        server_config.alpn_protocols = vec![b"h3".to_vec()];
        let mut server =
            ServerConnection::new(Arc::new(server_config), Version::V1, b"server-params".to_vec())
                .unwrap();

        let name = CString::new("localhost").unwrap();
        let alpn_bytes = b"h3";
        let alpn = [rustls_slice_bytes::from(&alpn_bytes[..])];
        let mut conn: *mut rustls_quic_connection = null_mut();
        let r = rustls_quic_connection::rustlsq_quic_client_connection_new(
            config,
            RUSTLS_QUIC_VERSION_V1,
            name.as_ptr(),
            alpn.as_ptr(),
            1,
            b"client-params".as_ptr(),
            13,
            &mut conn,
        );
        assert_eq!(r, rustls_result::Ok);

        let log = |s: String| events.lock().unwrap().push(s);
        let mut done = false;
        for round in 0..10 {
            // client -> server
            loop {
                let mut out = vec![0u8; 16384];
                let (mut n, mut keys) = (0usize, 0u32);
                let r = rustls_quic_connection::rustlsq_quic_connection_write_hs(
                    conn, out.as_mut_ptr(), out.len(), &mut n, &mut keys,
                );
                assert_eq!(r, rustls_result::Ok);
                log(format!("round {round}: client write_hs -> {n} bytes, keys {keys}"));
                if n > 0 {
                    server.read_hs(&out[..n]).unwrap();
                }
                if n == 0 && keys == 0 {
                    break;
                }
            }
            // server -> client: the bytes of each encryption level are handed over separately
            loop {
                let mut buf = Vec::new();
                let kc = server.write_hs(&mut buf);
                if buf.is_empty() && kc.is_none() {
                    break;
                }
                log(format!("round {round}: server write_hs -> {} bytes, keychange {}", buf.len(), kc.is_some()));
                if !buf.is_empty() {
                    let r = rustls_quic_connection::rustlsq_quic_connection_read_hs(
                        conn, buf.as_ptr(), buf.len(),
                    );
                    log(format!("round {round}: client read_hs({} bytes) -> {r:?}", buf.len()));
                    assert_eq!(r, rustls_result::Ok);
                }
            }
            // one more round once the client is done reading: it still has its Finished to send
            if done {
                break;
            }
            if !rustls_quic_connection::rustlsq_quic_connection_is_handshaking(conn) {
                done = true;
            }
        }
        for e in events.lock().unwrap().iter() {
            println!("{e}");
        }
        assert!(done, "the client handshake did not finish");
        let (mut p, mut l) = (null(), 0usize);
        assert!(rustls_quic_connection::rustlsq_quic_connection_peer_transport_parameters(conn, &mut p, &mut l));
        assert_eq!(unsafe { std::slice::from_raw_parts(p, l) }, b"server-params");
        for kind in 1..=4 {
            let (mut s, mut n) = ([0u8; 64], 0usize);
            assert!(rustls_quic_connection::rustlsq_quic_connection_secret(conn, kind, s.as_mut_ptr(), 64, &mut n));
            assert_eq!(n, 48);
        }
        let suite = rustls_quic_connection::rustlsq_quic_connection_cipher_suite(conn);
        println!("cipher suite 0x{suite:04x}");
        assert!((0x1301..=0x1303).contains(&suite));
        rustls_quic_connection::rustlsq_quic_connection_free(conn);
    }
}
