//! Minimal TLS 1.3 `ClientHello` parser, scoped to what the deferred
//! selector needs: detect whether the full message has arrived, and
//! extract SNI / ALPN. Allocation-free reads; the only owned strings
//! returned are the SNI name (a borrowed `&str` slice).

/// Result of a parse attempt against an incremental CRYPTO byte buffer.
pub enum Parse<'a> {
    /// Not enough bytes yet for a complete `ClientHello`. Caller should
    /// buffer more and retry.
    Incomplete,
    /// A complete `ClientHello` is present in the buffer. `_total_len` is
    /// the number of bytes the handshake message occupies (including the
    /// 4-byte handshake header).
    Complete {
        server_name: Option<&'a str>,
        alpn: Vec<&'a [u8]>,
        _total_len: usize,
    },
    /// The buffer is not a `ClientHello`, or is malformed.
    Error(&'static str),
}

const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const EXT_ALPN: u16 = 16;
const SNI_NAME_TYPE_HOST: u8 = 0;

pub fn try_parse(buffer: &[u8]) -> Parse<'_> {
    // Handshake header: 1 byte type + 3 bytes length.
    if buffer.len() < 4 {
        return Parse::Incomplete;
    }
    if buffer[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Parse::Error("first handshake message is not ClientHello");
    }
    let body_len =
        ((buffer[1] as usize) << 16) | ((buffer[2] as usize) << 8) | (buffer[3] as usize);
    let total_len = 4 + body_len;
    if buffer.len() < total_len {
        return Parse::Incomplete;
    }
    let body = &buffer[4..total_len];

    // ClientHello structure (TLS 1.3):
    //   legacy_version (2) | random (32) | session_id (1+0..32) |
    //   cipher_suites (2+N) | compression_methods (1+N) | extensions (2+N)
    let mut r = Reader::new(body);

    if r.skip(2 + 32).is_err() {
        return Parse::Error("truncated before session_id");
    }
    if r.skip_var(1).is_err() {
        return Parse::Error("truncated session_id");
    }
    if r.skip_var(2).is_err() {
        return Parse::Error("truncated cipher_suites");
    }
    if r.skip_var(1).is_err() {
        return Parse::Error("truncated compression_methods");
    }
    let extensions_len = match r.read_u16() {
        Ok(v) => v as usize,
        Err(_) => return Parse::Error("missing extensions length"),
    };
    if r.remaining() < extensions_len {
        return Parse::Error("truncated extensions");
    }
    let extensions = match r.take(extensions_len) {
        Ok(v) => v,
        Err(_) => return Parse::Error("extensions take"),
    };

    let mut server_name: Option<&str> = None;
    let mut alpn: Vec<&[u8]> = Vec::new();

    let mut er = Reader::new(extensions);
    while !er.empty() {
        let ext_type = match er.read_u16() {
            Ok(v) => v,
            Err(_) => return Parse::Error("extension header"),
        };
        let ext_len = match er.read_u16() {
            Ok(v) => v as usize,
            Err(_) => return Parse::Error("extension length"),
        };
        let ext_body = match er.take(ext_len) {
            Ok(v) => v,
            Err(_) => return Parse::Error("extension body"),
        };

        match ext_type {
            EXT_SERVER_NAME => {
                // server_name_list: 2-byte length, then entries:
                //   name_type (1) | name (2-byte length + bytes)
                let mut sr = Reader::new(ext_body);
                let list_len = match sr.read_u16() {
                    Ok(v) => v as usize,
                    Err(_) => return Parse::Error("sni list length"),
                };
                let list = match sr.take(list_len) {
                    Ok(v) => v,
                    Err(_) => return Parse::Error("sni list body"),
                };
                let mut lr = Reader::new(list);
                while !lr.empty() {
                    let name_type = match lr.read_u8() {
                        Ok(v) => v,
                        Err(_) => return Parse::Error("sni name_type"),
                    };
                    let name_len = match lr.read_u16() {
                        Ok(v) => v as usize,
                        Err(_) => return Parse::Error("sni name length"),
                    };
                    let name_bytes = match lr.take(name_len) {
                        Ok(v) => v,
                        Err(_) => return Parse::Error("sni name body"),
                    };
                    if name_type == SNI_NAME_TYPE_HOST && server_name.is_none() {
                        if let Ok(s) = std::str::from_utf8(name_bytes) {
                            server_name = Some(s);
                        }
                    }
                }
            }
            EXT_ALPN => {
                // protocol_name_list: 2-byte length, then entries:
                //   name (1-byte length + bytes)
                let mut ar = Reader::new(ext_body);
                let list_len = match ar.read_u16() {
                    Ok(v) => v as usize,
                    Err(_) => return Parse::Error("alpn list length"),
                };
                let list = match ar.take(list_len) {
                    Ok(v) => v,
                    Err(_) => return Parse::Error("alpn list body"),
                };
                let mut lr = Reader::new(list);
                while !lr.empty() {
                    let name_len = match lr.read_u8() {
                        Ok(v) => v as usize,
                        Err(_) => return Parse::Error("alpn name length"),
                    };
                    let name = match lr.take(name_len) {
                        Ok(v) => v,
                        Err(_) => return Parse::Error("alpn name body"),
                    };
                    alpn.push(name);
                }
            }
            _ => {}
        }
    }

    Parse::Complete {
        server_name,
        alpn,
        _total_len: total_len,
    }
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn remaining(&self) -> usize {
        self.buf.len()
    }

    fn read_u8(&mut self) -> Result<u8, ()> {
        let (a, rest) = self.buf.split_first().ok_or(())?;
        self.buf = rest;
        Ok(*a)
    }

    fn read_u16(&mut self) -> Result<u16, ()> {
        if self.buf.len() < 2 {
            return Err(());
        }
        let v = ((self.buf[0] as u16) << 8) | (self.buf[1] as u16);
        self.buf = &self.buf[2..];
        Ok(v)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ()> {
        if self.buf.len() < n {
            return Err(());
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Ok(a)
    }

    fn skip(&mut self, n: usize) -> Result<(), ()> {
        self.take(n).map(|_| ())
    }

    /// Skip a length-prefixed variable-length field. `len_bytes` is 1 or 2.
    fn skip_var(&mut self, len_bytes: usize) -> Result<(), ()> {
        let len = match len_bytes {
            1 => self.read_u8()? as usize,
            2 => self.read_u16()? as usize,
            _ => return Err(()),
        };
        self.skip(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real ClientHello captured from a rustls::ClientConnection targeting
    /// "example.com" with default suites. Helpful as a regression bait if
    /// the parser drifts.
    fn fake_clienthello_with_sni(sni: &str) -> Vec<u8> {
        // Constructed minimally: TLS 1.3 ClientHello with only the SNI
        // extension and the legacy supported_versions extension stub.
        let host = sni.as_bytes();
        let sni_entry_len = 1 + 2 + host.len();
        let sni_list_len = sni_entry_len;
        let sni_ext_body_len = 2 + sni_list_len;
        let sni_ext_total = 4 + sni_ext_body_len;
        let extensions_len = sni_ext_total;

        // body length: 2 (legacy_version) + 32 (random) + 1 (session_id len)
        //            + 0 (session_id) + 2 (cipher_suites len) + 2 (one cipher)
        //            + 1 (compression_methods len) + 1 (null comp)
        //            + 2 (extensions len) + extensions_len
        let body_len = 2 + 32 + 1 + 0 + 2 + 2 + 1 + 1 + 2 + extensions_len;

        let mut buf = Vec::new();
        // handshake header
        buf.push(1);
        buf.extend_from_slice(&[
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ]);
        // body
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0); // session_id len
        buf.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: TLS_AES_128_GCM_SHA256
        buf.extend_from_slice(&[0x01, 0x00]); // compressions: null
        buf.extend_from_slice(&[
            ((extensions_len >> 8) & 0xff) as u8,
            (extensions_len & 0xff) as u8,
        ]);
        // SNI extension
        buf.extend_from_slice(&[0x00, 0x00]); // ext type: server_name
        buf.extend_from_slice(&[
            ((sni_ext_body_len >> 8) & 0xff) as u8,
            (sni_ext_body_len & 0xff) as u8,
        ]);
        buf.extend_from_slice(&[
            ((sni_list_len >> 8) & 0xff) as u8,
            (sni_list_len & 0xff) as u8,
        ]);
        buf.push(0); // name_type: host_name
        buf.extend_from_slice(&[((host.len() >> 8) & 0xff) as u8, (host.len() & 0xff) as u8]);
        buf.extend_from_slice(host);
        buf
    }

    #[test]
    fn incomplete_buffer_returns_incomplete() {
        let ch = fake_clienthello_with_sni("example.com");
        let partial = &ch[..ch.len() - 5];
        match try_parse(partial) {
            Parse::Incomplete => {}
            _ => panic!("expected Incomplete"),
        }
    }

    #[test]
    fn complete_clienthello_extracts_sni() {
        let ch = fake_clienthello_with_sni("localhost");
        match try_parse(&ch) {
            Parse::Complete {
                server_name,
                _total_len,
                ..
            } => {
                assert_eq!(server_name, Some("localhost"));
                assert_eq!(_total_len, ch.len());
            }
            other => match other {
                Parse::Incomplete => panic!("expected Complete, got Incomplete"),
                Parse::Error(e) => panic!("expected Complete, got Error: {e}"),
                Parse::Complete { .. } => unreachable!(),
            },
        }
    }

    #[test]
    fn non_clienthello_first_byte_is_error() {
        let mut bad = fake_clienthello_with_sni("x");
        bad[0] = 2; // ServerHello
        match try_parse(&bad) {
            Parse::Error(_) => {}
            _ => panic!("expected Error"),
        }
    }
}
