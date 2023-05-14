use std::io::Error;
use log::trace;
use cio::{CioStream, CioListener};

/**
 * Log
 */

pub enum LogLevel {
    None = 0,
    Trace,
    Debug,
    Info,
    Notice,
    Warn,
    Error,
    Fatal,
}

pub fn log_set_level(level: LogLevel) {
    unsafe {
        srrp_sys::log_set_level(level as i32);
    }
}

/**
 * SrrpConnect
 */

pub struct SrrpConnect {
    pub conn: *mut srrp_sys::srrp_connect,
    pub stream: CioStream,
}

unsafe impl Send for SrrpConnect {}
unsafe impl Sync for SrrpConnect {}

impl Drop for SrrpConnect {
    fn drop(&mut self) {
        unsafe {
            trace!("drop SrrpConnect:{:#08x}", self.conn as u64);
            srrp_sys::srrpc_drop(self.conn);
        }
    }
}

impl SrrpConnect {
    pub fn new(stream: CioStream, nodeid: &str) -> Result<SrrpConnect, Error> {
        let nodeid = std::ffi::CString::new(nodeid).unwrap();
        unsafe {
            let conn = srrp_sys::srrpc_new(
                stream.stream as *mut _, 0, nodeid.as_ptr() as *const i8);
            if conn.is_null() {
                Err(Error::last_os_error())
            } else {
                Ok(SrrpConnect {
                    conn: conn,
                    stream: stream,
                })
            }
        }
    }

    pub fn wait(&self, usec: u64) -> i32 {
        unsafe { return srrp_sys::srrpc_wait(self.conn, usec); }
    }

    pub fn wait_until(&self) -> i32 {
        unsafe { return srrp_sys::srrpc_wait_until(self.conn); }
    }

    pub fn wait_response(&self, srcid: &str, anchor: &str) -> Option<SrrpPacket> {
        let srcid = std::ffi::CString::new(srcid).unwrap();
        let anchor = std::ffi::CString::new(anchor).unwrap();
        unsafe {
            let pac = srrp_sys::srrpc_wait_response(
                self.conn,
                srcid.as_ptr() as *const i8,
                anchor.as_ptr() as *const i8,
            );
            if pac.is_null() {
                None
            } else {
                Some(Srrp::from_raw_packet(pac))
            }
        }
    }

    pub fn iter(&self) -> Option<SrrpPacket> {
        unsafe {
            let pac = srrp_sys::srrpc_iter(self.conn);
            if pac.is_null() {
                None
            } else {
                Some(Srrp::from_raw_packet(pac))
            }
        }
    }

    pub fn iter_pending(&self) -> Option<SrrpPacket> {
        unsafe {
            let pac = srrp_sys::srrpc_iter_pending(self.conn);
            if pac.is_null() {
                None
            } else {
                Some(Srrp::from_raw_packet(pac))
            }
        }
    }

    pub fn send(&self, pac: &SrrpPacket) -> i32 {
        unsafe { return srrp_sys::srrpc_send(self.conn, pac.pac); }
    }

    pub fn pending(&self, pac: &SrrpPacket) -> i32 {
        unsafe { return srrp_sys::srrpc_pending(self.conn, pac.pac); }
    }

    pub fn finished(&self, pac: &SrrpPacket) -> i32 {
        unsafe { return srrp_sys::srrpc_finished(self.conn, pac.pac); }
    }
}

/**
 * SrrpRouter
 */

pub struct SrrpRouter {
    pub router: *mut srrp_sys::srrp_router,
    pub listeners: Vec<CioListener>,
    pub streams: Vec<CioStream>,
}

unsafe impl Send for SrrpRouter {}
unsafe impl Sync for SrrpRouter {}

impl Drop for SrrpRouter {
    fn drop(&mut self) {
        unsafe {
            trace!("drop SrrpRouter:{:#08x}", self.router as u64);
            srrp_sys::srrpr_drop(self.router);
        }
    }
}

impl SrrpRouter {
    pub fn new() -> Result<SrrpRouter, Error> {
        unsafe {
            let router = srrp_sys::srrpr_new();
            if router.is_null() {
                Err(Error::last_os_error())
            } else {
                Ok(SrrpRouter{
                    router: router,
                    listeners: Vec::new(),
                    streams: Vec::new(),
                })
            }
        }
    }

    pub fn add_listener(&mut self, listener: CioListener, nodeid: &str) {
        let nodeid = std::ffi::CString::new(nodeid).unwrap();
        unsafe {
            srrp_sys::srrpr_add_listener(
                self.router, listener.listener as *mut _, 0, nodeid.as_ptr() as *const i8);
            self.listeners.push(listener);
        }
    }

    pub fn add_stream(&mut self, stream: CioStream, nodeid: &str) {
        let nodeid = std::ffi::CString::new(nodeid).unwrap();
        unsafe {
            srrp_sys::srrpr_add_stream(
                self.router, stream.stream as *mut _, 0, nodeid.as_ptr() as *const i8);
            self.streams.push(stream);
        }
    }

    pub fn wait(&self, usec: u64) -> i32 {
        unsafe { return srrp_sys::srrpr_wait(self.router, usec); }
    }

    pub fn iter(&self) -> Option<SrrpPacket> {
        unsafe {
            let pac = srrp_sys::srrpr_iter(self.router);
            if pac.is_null() {
                None
            } else {
                Some(Srrp::from_raw_packet(pac))
            }
        }
    }

    pub fn send(&self, pac: &SrrpPacket) -> i32 {
        unsafe { return srrp_sys::srrpr_send(self.router, pac.pac); }
    }

    pub fn forward(&self, pac: &SrrpPacket) -> i32 {
        unsafe { return srrp_sys::srrpr_forward(self.router, pac.pac); }
    }
}

/**
 * SrrPacket
 */

pub struct SrrpPacket {
    pub leader: i8,
    pub fin: u8,
    pub ver: u16,
    pub payload_type: u8,
    pub packet_len: u16,
    pub payload_len: u32,
    pub srcid: String,
    pub dstid: String,
    pub anchor: String,
    pub payload: String,
    pub crc16: u16,
    pub raw: Vec<u8>,
    pub pac: *mut srrp_sys::srrp_packet,
    pub owned: bool,
}

impl Drop for SrrpPacket {
    fn drop(&mut self) {
        unsafe {
            if self.owned {
                srrp_sys::srrp_free(self.pac);
            }
        }
    }
}

pub struct Srrp {}

impl Srrp {
    fn from_raw_packet(pac: *mut srrp_sys::srrp_packet) -> SrrpPacket {
        unsafe {
            let packet_len = srrp_sys::srrp_get_packet_len(pac);
            let srcid = srrp_sys::srrp_get_srcid(pac);
            let dstid = srrp_sys::srrp_get_dstid(pac);
            let anchor = srrp_sys::srrp_get_anchor(pac);
            let payload = srrp_sys::srrp_get_payload(pac);
            let raw = srrp_sys::srrp_get_raw(pac);
            SrrpPacket {
                leader: srrp_sys::srrp_get_leader(pac),
                fin: srrp_sys::srrp_get_fin(pac),
                ver: srrp_sys::srrp_get_ver(pac),
                payload_type: srrp_sys::srrp_get_payload_type(pac),
                packet_len: packet_len,
                payload_len: srrp_sys::srrp_get_payload_len(pac),
                srcid: std::ffi::CStr::from_ptr(srcid).to_str().unwrap().to_owned(),
                dstid: std::ffi::CStr::from_ptr(dstid).to_str().unwrap().to_owned(),
                anchor: std::ffi::CStr::from_ptr(anchor).to_str().unwrap().to_owned(),
                payload: match payload.is_null() {
                    true => String::from(""),
                    _ => std::ffi::CStr::from_ptr(payload as *const i8)
                        .to_str().unwrap().to_owned(),
                },
                crc16: srrp_sys::srrp_get_crc16(pac),
                raw: {
                    let mut v: Vec<u8> = Vec::new();
                    for i in 0..packet_len {
                        v.push(*(raw).offset(i as isize));
                    }
                    v
                },
                pac: pac,
                owned: false,
            }
        }
    }

    pub fn next_packet_offset(buf: &[u8]) -> u32 {
        unsafe {
            srrp_sys::srrp_next_packet_offset(
                buf.as_ptr() as *const u8, buf.len() as u32)
        }
    }

    pub fn parse(buf: &[u8]) -> Option<SrrpPacket> {
        unsafe {
            let pac = srrp_sys::srrp_parse(buf.as_ptr() as *const u8, buf.len() as u32);
            if pac.is_null() {
                None
            } else {
                Some(Srrp::from_raw_packet(pac))
            }
        }
    }

    pub fn new(leader: char, fin: u8, srcid: &str, dstid: &str, anchor: &str, payload: &str)
               -> Option<SrrpPacket> {
        let srcid = std::ffi::CString::new(srcid).unwrap();
        let dstid = std::ffi::CString::new(dstid).unwrap();
        let anchor = std::ffi::CString::new(anchor).unwrap();
        unsafe {
            let pac = srrp_sys::srrp_new(
                leader as i8, fin,
                srcid.as_ptr() as *const i8,
                dstid.as_ptr() as *const i8,
                anchor.as_ptr() as *const i8,
                payload.as_ptr() as *const u8,
                payload.len() as u32,
            );
            if pac.is_null() {
                None
            } else {
                let mut tmp = Srrp::from_raw_packet(pac);
                tmp.owned = true;
                Some(tmp)
            }
        }
    }

    pub fn new_ctrl(srcid: &str, anchor: &str, payload: &str) -> Option<SrrpPacket> {
        return Self::new('=', 1, srcid, "", anchor, payload);
    }

    pub fn new_request(srcid: &str, dstid: &str, anchor: &str, payload: &str)
                       -> Option<SrrpPacket> {
        return Self::new('>', 1, srcid, dstid, anchor, payload);
    }

    pub fn new_response(srcid: &str, dstid: &str, anchor: &str, payload: &str)
                        -> Option<SrrpPacket> {
        return Self::new('<', 1, srcid, dstid, anchor, payload);
    }

    pub fn new_subscribe(anchor: &str, payload: &str) -> Option<SrrpPacket> {
        return Self::new('+', 1, "", "", anchor, payload);
    }

    pub fn new_unsubscribe(anchor: &str, payload: &str) -> Option<SrrpPacket> {
        return Self::new('-', 1, "", "", anchor, payload);
    }

    pub fn new_publish(anchor: &str, payload: &str) -> Option<SrrpPacket> {
        return Self::new('@', 1, "", "", anchor, payload);
    }
}
