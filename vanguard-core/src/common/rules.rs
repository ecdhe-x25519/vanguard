use crate::common::{
    ip::*,
};

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct Tuple5 {
    pub src_ip: EbpfIp,
    pub dst_ip: EbpfIp,
    pub src_port: EbpfPort,
    pub dst_port: EbpfPort,
    pub proto: EbpfProto,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for Tuple5 {}