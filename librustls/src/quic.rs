//! A C API over `rustls::quic`: a QUIC client handshake driven by the caller, who moves the
//! handshake bytes between this connection and the QUIC packets of its own transport.
//!
//! Experimental. The functions are named as upstream would name them; the downstream renaming
//! of the exported symbols is applied on top by a script.

use std::ffi::c_char;
use std::ptr::{NonNull, null};
use std::sync::{Arc, Mutex};

use libc::size_t;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::quic::{ClientConnection, KeyChange, Version};
use rustls::{ClientConfig, KeyLog};

use crate::certificate::rustls_certificate;
use crate::client::rustls_client_config;
use crate::error::{map_error, rustls_result};
use crate::ffi::{
    Castable, OwnershipBox, free_box, set_boxed_mut_ptr, try_clone_arc, try_cstr, try_mut_from_ptr,
    try_mut_from_ptr_ptr, try_ref_from_ptr, try_slice, try_slice_mut,
};
use crate::panic::ffi_panic_boundary;
use crate::rslice::rustls_slice_bytes;

/// The QUIC version a connection runs, which governs version-specific behaviour of TLS.
pub const RUSTLS_QUIC_VERSION_V1: u32 = 1;
pub const RUSTLS_QUIC_VERSION_V2: u32 = 2;
pub const RUSTLS_QUIC_VERSION_V1_DRAFT: u32 = 0x1d;

/// Which keys `rustls_quic_connection_write_hs` made available after the bytes it wrote.
pub const RUSTLS_QUIC_KEYS_NONE: u32 = 0;
pub const RUSTLS_QUIC_KEYS_HANDSHAKE: u32 = 1;
pub const RUSTLS_QUIC_KEYS_ONE_RTT: u32 = 2;

/// Which traffic secret `rustls_quic_connection_get_secret` returns.
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
    /// handshake bytes that did not fit in the caller's buffer yet
    unsent: Vec<u8>,
    /// the keys that become available once `unsent` is empty
    pending: Option<KeyChange>,
}

impl Castable for rustls_quic_connection {
    type Ownership = OwnershipBox;
    type RustType = QuicClient;
}

impl rustls_quic_connection {
    /// Create a QUIC client connection. `params` is the TLS-encoded QUIC transport parameters
    /// to send. `alpn_protocols` overrides the ALPN of the config as
    /// `rustls_client_connection_new_alpn` does. The config must allow TLS 1.3.
    #[no_mangle]
    pub extern "C" fn rustls_quic_client_connection_new(
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
                QuicClient { conn, secrets, unsent: Vec::new(), pending: None },
            );
            rustls_result::Ok
        }
    }

    /// Give the connection the handshake bytes that arrived in CRYPTO frames, in order, at the
    /// encryption level they were received at.
    #[no_mangle]
    pub extern "C" fn rustls_quic_connection_read_hs(
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
    /// connection may have new keys: `*keys_out` says which (`RUSTLS_QUIC_KEYS_*`).
    ///
    /// Writes at most `cap` bytes to `out` and the count to `*len_out`. If there are more, they are
    /// kept: call again, and `*keys_out` stays `RUSTLS_QUIC_KEYS_NONE` until the call that writes the
    /// last bytes of the level. Call this after every `rustls_quic_connection_read_hs`: the bytes of
    /// two levels would run together otherwise.
    #[no_mangle]
    pub extern "C" fn rustls_quic_connection_write_hs(
        conn: *mut rustls_quic_connection,
        out: *mut u8,
        cap: size_t,
        len_out: *mut size_t,
        keys_out: *mut u32,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let conn = try_mut_from_ptr!(conn);
            let out = try_slice_mut!(out, cap);
            let (Some(len_out), Some(keys_out)) = (NonNull::new(len_out), NonNull::new(keys_out))
            else {
                return rustls_result::NullParameter;
            };
            if conn.unsent.is_empty() && conn.pending.is_none() {
                conn.pending = conn.conn.write_hs(&mut conn.unsent);
            }
            let n = conn.unsent.len().min(out.len());
            out[..n].copy_from_slice(&conn.unsent[..n]);
            conn.unsent.drain(..n);
            let keys = if conn.unsent.is_empty() {
                match conn.pending.take() {
                    None => RUSTLS_QUIC_KEYS_NONE,
                    Some(KeyChange::Handshake { .. }) => RUSTLS_QUIC_KEYS_HANDSHAKE,
                    Some(KeyChange::OneRtt { .. }) => RUSTLS_QUIC_KEYS_ONE_RTT,
                }
            } else {
                RUSTLS_QUIC_KEYS_NONE
            };
            unsafe {
                len_out.write(n);
                keys_out.write(keys);
            }
            rustls_result::Ok
        }
    }

    /// Whether the handshake is still going on.
    #[no_mangle]
    pub extern "C" fn rustls_quic_connection_is_handshaking(
        conn: *const rustls_quic_connection,
    ) -> bool {
        ffi_panic_boundary! {
            crate::ffi::try_ref_from_ptr!(conn).conn.is_handshaking()
        }
    }

    /// Get the TLS alert to send when the handshake failed (check it after `rustls_quic_connection_read_hs`
    /// returned an error). Stores it in `alert_out` and returns `RUSTLS_RESULT_OK`, or returns
    /// `RUSTLS_RESULT_NOT_FOUND` when there is none.
    #[no_mangle]
    pub extern "C" fn rustls_quic_connection_get_alert(
        conn: *const rustls_quic_connection,
        alert_out: *mut u8,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let conn = try_ref_from_ptr!(conn);
            let Some(alert_out) = NonNull::new(alert_out) else {
                return rustls_result::NullParameter;
            };
            match conn.conn.alert() {
                Some(alert) => {
                    unsafe { alert_out.write(u8::from(alert)) };
                    rustls_result::Ok
                }
                None => rustls_result::NotFound,
            }
        }
    }

    /// Copy a traffic secret (`RUSTLS_QUIC_SECRET_*`) to `out`, which has room for `cap` bytes, and its length
    /// to `*len_out`.
    ///
    /// Returns `RUSTLS_RESULT_NOT_FOUND` while the secret does not exist yet, `RUSTLS_RESULT_INVALID_PARAMETER`
    /// for an unknown `kind`, and `RUSTLS_RESULT_INSUFFICIENT_SIZE` if it does not fit (48 bytes are enough
    /// for every secret). Each secret exists from the moment the handshake bytes that give it have been read
    /// (`rustls_quic_connection_read_hs`), which is before `rustls_quic_connection_write_hs` reports the keys.
    #[no_mangle]
    pub extern "C" fn rustls_quic_connection_get_secret(
        conn: *const rustls_quic_connection,
        kind: u32,
        out: *mut u8,
        cap: size_t,
        len_out: *mut size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let conn = try_ref_from_ptr!(conn);
            let out = try_slice_mut!(out, cap);
            let Some(len_out) = NonNull::new(len_out) else {
                return rustls_result::NullParameter;
            };
            let store = conn.secrets.lock().unwrap();
            let Some(secret) = store.get(kind as usize) else {
                return rustls_result::InvalidParameter;
            };
            let Some(secret) = secret else {
                return rustls_result::NotFound;
            };
            if secret.len() > out.len() {
                return rustls_result::InsufficientSize;
            }
            out[..secret.len()].copy_from_slice(secret);
            unsafe { len_out.write(secret.len()) };
            rustls_result::Ok
        }
    }

    /// Retrieves the [IANA registered cipher suite identifier] agreed with the peer (0x1301, 0x1302 or
    /// 0x1303 for TLS 1.3).
    ///
    /// This returns `TLS_NULL_WITH_NULL_NULL` (0x0000) until the ciphersuite is agreed.
    ///
    /// [IANA registered cipher suite identifier]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
    #[no_mangle]
    pub extern "C" fn rustls_quic_connection_get_negotiated_ciphersuite(
        conn: *const rustls_quic_connection,
    ) -> u16 {
        ffi_panic_boundary! {
            try_ref_from_ptr!(conn)
                .conn
                .negotiated_cipher_suite()
                .map(|cs| u16::from(cs.suite()))
                .unwrap_or(0)
        }
    }

    /// Get the `i`-th certificate that the server sent (0 is the end-entity certificate), or NULL when there is
    /// none: before the handshake has got that far, or `i` is past the last. Use `rustls_certificate_get_der` on
    /// it. The pointer is valid until the connection is changed or freed.
    #[no_mangle]
    pub extern "C" fn rustls_quic_connection_get_peer_certificate<'a>(
        conn: *const rustls_quic_connection,
        i: size_t,
    ) -> *const rustls_certificate<'a> {
        ffi_panic_boundary! {
            match try_ref_from_ptr!(conn)
                .conn
                .peer_certificates()
                .and_then(|certs| certs.get(i))
            {
                Some(cert) => cert as *const CertificateDer as *const _,
                None => null(),
            }
        }
    }

    /// Get the QUIC transport parameters of the peer, as they came in the handshake. Stores a pointer to a
    /// borrowed buffer of bytes, and its length, in the output parameters; NULL and 0 while they have not
    /// arrived. The buffer is valid until the connection is changed or freed.
    ///
    /// If `conn` or either output parameter is NULL, both output values are unchanged.
    #[no_mangle]
    pub extern "C" fn rustls_quic_connection_get_peer_transport_parameters(
        conn: *const rustls_quic_connection,
        params_out: *mut *const u8,
        params_out_len: *mut size_t,
    ) {
        ffi_panic_boundary! {
            let conn = try_ref_from_ptr!(conn);
            let (Some(params_out), Some(params_out_len)) =
                (NonNull::new(params_out), NonNull::new(params_out_len))
            else {
                return;
            };
            match conn.conn.quic_transport_parameters() {
                Some(params) => unsafe {
                    params_out.write(params.as_ptr());
                    params_out_len.write(params.len());
                },
                None => unsafe {
                    params_out.write(null());
                    params_out_len.write(0);
                },
            }
        }
    }

    /// Free a `rustls_quic_connection`. Calling with NULL is fine.
    #[no_mangle]
    pub extern "C" fn rustls_quic_connection_free(conn: *mut rustls_quic_connection) {
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

    /// The ClientHello, taken in pieces of 100 bytes, is the one that is taken at once: what does not fit is kept.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn write_hs_keeps_what_does_not_fit() {
        let take = |cap: usize| -> Vec<u8> {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let roots = RootCertStore::empty();
            let config = ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let config: *const rustls_client_config = to_arc_const_ptr(config);
            let name = CString::new("localhost").unwrap();
            let alpn_bytes = b"h3";
            let alpn = [rustls_slice_bytes::from(&alpn_bytes[..])];
            let mut conn: *mut rustls_quic_connection = null_mut();
            let r = rustls_quic_connection::rustls_quic_client_connection_new(
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
            let mut all = Vec::new();
            loop {
                let mut out = vec![0u8; cap];
                let (mut n, mut keys) = (0usize, 0u32);
                let r = rustls_quic_connection::rustls_quic_connection_write_hs(
                    conn,
                    out.as_mut_ptr(),
                    cap,
                    &mut n,
                    &mut keys,
                );
                assert_eq!(r, rustls_result::Ok);
                all.extend_from_slice(&out[..n]);
                if n == 0 {
                    break;
                }
            }
            rustls_quic_connection::rustls_quic_connection_free(conn);
            all
        };
        let at_once = take(16384);
        assert!(at_once.len() > 1000);
        let in_pieces = take(100);
        assert_eq!(at_once.len(), in_pieces.len());
        // the random of the ClientHello differs between connections: compare the framing, not the bytes
        assert_eq!(at_once[..4], in_pieces[..4]);
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
        let leaf_der = certs[0].as_ref().to_vec();
        let key = PrivateKeyDer::from_pem_file(dir("localhost/key.pem")).unwrap();
        let mut server_config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        server_config.alpn_protocols = vec![b"h3".to_vec()];
        let mut server = ServerConnection::new(
            Arc::new(server_config),
            Version::V1,
            b"server-params".to_vec(),
        )
        .unwrap();

        let name = CString::new("localhost").unwrap();
        let alpn_bytes = b"h3";
        let alpn = [rustls_slice_bytes::from(&alpn_bytes[..])];
        let mut conn: *mut rustls_quic_connection = null_mut();
        let r = rustls_quic_connection::rustls_quic_client_connection_new(
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
                let r = rustls_quic_connection::rustls_quic_connection_write_hs(
                    conn,
                    out.as_mut_ptr(),
                    out.len(),
                    &mut n,
                    &mut keys,
                );
                assert_eq!(r, rustls_result::Ok);
                log(format!(
                    "round {round}: client write_hs -> {n} bytes, keys {keys}"
                ));
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
                log(format!(
                    "round {round}: server write_hs -> {} bytes, keychange {}",
                    buf.len(),
                    kc.is_some()
                ));
                if !buf.is_empty() {
                    let r = rustls_quic_connection::rustls_quic_connection_read_hs(
                        conn,
                        buf.as_ptr(),
                        buf.len(),
                    );
                    log(format!(
                        "round {round}: client read_hs({} bytes) -> {r:?}",
                        buf.len()
                    ));
                    assert_eq!(r, rustls_result::Ok);
                }
            }
            // one more round once the client is done reading: it still has its Finished to send
            if done {
                break;
            }
            if !rustls_quic_connection::rustls_quic_connection_is_handshaking(conn) {
                done = true;
            }
        }
        for e in events.lock().unwrap().iter() {
            println!("{e}");
        }
        assert!(done, "the client handshake did not finish");
        let (mut p, mut l) = (null(), 0usize);
        rustls_quic_connection::rustls_quic_connection_get_peer_transport_parameters(
            conn, &mut p, &mut l,
        );
        assert_eq!(
            unsafe { std::slice::from_raw_parts(p, l) },
            b"server-params"
        );
        for kind in 1..=4 {
            let (mut s, mut n) = ([0u8; 64], 0usize);
            assert_eq!(
                rustls_quic_connection::rustls_quic_connection_get_secret(
                    conn,
                    kind,
                    s.as_mut_ptr(),
                    64,
                    &mut n
                ),
                rustls_result::Ok
            );
            assert_eq!(n, 48);
        }
        // a buffer that is too small, and a kind that does not exist
        let (mut s, mut n) = ([0u8; 64], 0usize);
        assert_eq!(
            rustls_quic_connection::rustls_quic_connection_get_secret(
                conn,
                1,
                s.as_mut_ptr(),
                8,
                &mut n
            ),
            rustls_result::InsufficientSize
        );
        assert_eq!(
            rustls_quic_connection::rustls_quic_connection_get_secret(
                conn,
                9,
                s.as_mut_ptr(),
                64,
                &mut n
            ),
            rustls_result::InvalidParameter
        );
        // the certificate that the server sent, through the call that TLS connections have
        let cert = rustls_quic_connection::rustls_quic_connection_get_peer_certificate(conn, 0);
        assert!(!cert.is_null());
        let (mut c, mut cl) = (null(), 0usize);
        assert_eq!(
            crate::certificate::rustls_certificate_get_der(cert, &mut c, &mut cl),
            rustls_result::Ok
        );
        assert_eq!(unsafe { std::slice::from_raw_parts(c, cl) }, &leaf_der[..]);
        assert!(
            rustls_quic_connection::rustls_quic_connection_get_peer_certificate(conn, 99).is_null()
        );
        // no alert: the handshake did not fail
        let mut alert = 0u8;
        assert_eq!(
            rustls_quic_connection::rustls_quic_connection_get_alert(conn, &mut alert),
            rustls_result::NotFound
        );
        let suite = rustls_quic_connection::rustls_quic_connection_get_negotiated_ciphersuite(conn);
        println!("cipher suite 0x{suite:04x}");
        assert!((0x1301..=0x1303).contains(&suite));
        rustls_quic_connection::rustls_quic_connection_free(conn);
    }
}
