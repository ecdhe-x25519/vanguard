use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::{TcpHdr},
    udp::UdpHdr,
};

use core::mem;

use crate::common::commons::EbpfAction;

#[repr(C)]
pub struct OffsetEbpfPort { pub ofs: u16 }

#[repr(C)]
pub struct OffsetEbpfProto { pub ofs: u16 }

#[repr(C)]
pub struct OffsetEbpfMac { pub ofs: u16 }

#[repr(C)]
pub struct OffsetEbpfIp {
    pub ofs: u16,
    pub is_v6: bool,
}

#[repr(C)]
pub struct OffsetTuple7 {
    pub src_mac: OffsetEbpfMac,
    pub dst_mac: OffsetEbpfMac,
    pub src_ip: OffsetEbpfIp,
    pub dst_ip: OffsetEbpfIp,
    pub src_port: OffsetEbpfPort,
    pub dst_port: OffsetEbpfPort,
    pub proto: OffsetEbpfProto,
}

#[repr(C)]
pub struct OffsetCsum {
    pub l3_check: u16,
    pub l4_check: u16,
}

#[repr(C)]
pub struct OffsetCsumL { pub ofs: u16 }

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn read_offset<T: Copy>(data: usize, ofs: u16) -> T {
    let abs_ptr = (data + ofs as usize) as *const T;
    core::ptr::read_unaligned(abs_ptr)
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn write_offset<T: Copy>(data: usize, ofs: u16, val: T) {
    let abs_ptr = (data + ofs as usize) as *mut T;
    core::ptr::write_volatile(abs_ptr, val);
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn swap_offset<T: Copy>(data: usize, ofs_a: u16, ofs_b: u16) {
    let ptr_a = (data + ofs_a as usize) as *mut T;
    let ptr_b = (data + ofs_b as usize) as *mut T;

    let val_a = core::ptr::read_unaligned(ptr_a);
    let val_b = core::ptr::read_unaligned(ptr_b);

    core::ptr::write_volatile(ptr_a, val_b);
    core::ptr::write_volatile(ptr_b, val_a);
}

#[inline(always)]
#[allow(clippy::result_unit_err)]
pub fn ptr_mut_at<T>(
    data: usize,
    data_end: usize,
    offset: usize
) -> Result<*mut T, ()> {
    let len = mem::size_of::<T>();

    if data + offset + len > data_end {
        return Err(());
    }

    let ptr = (data + offset) as *mut T;
    Ok(ptr)
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn try_parse_ip(
    data: usize,
    data_end: usize,
    offset: usize,
) -> Result<(OffsetTuple7, OffsetCsum), EbpfAction> {
    let ethhdr: *mut EthHdr = match ptr_mut_at(data, data_end, offset) {
        Ok(hdr) => hdr,
        Err(_) => return Err(EbpfAction::DROP),
    };

    let src_mac = core::ptr::addr_of_mut!((*ethhdr).src_addr);
    let dst_mac = core::ptr::addr_of_mut!((*ethhdr).dst_addr);

    let l3_offset = offset + EthHdr::LEN;

    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {
            let iphdr: *mut Ipv4Hdr = match ptr_mut_at(data, data_end, EthHdr::LEN) {
                Ok(hdr) => hdr,
                Err(_) => return Err(EbpfAction::DROP),
            };

            let src_ip = core::ptr::addr_of_mut!((*iphdr).src_addr);
            let dst_ip = core::ptr::addr_of_mut!((*iphdr).dst_addr);

            let l3_csum = core::ptr::addr_of_mut!((*iphdr).check);

            let ip_len = (*iphdr).ihl() as usize * 4;
            let proto = match (*iphdr).proto() {
                Ok(p) => p,
                Err(_) => {
                    return Err(EbpfAction::DROP)
                }
            };

            let (
                src_port,
                dst_port,
                l4_csum
            ) = try_parse_proto(data, data_end, l3_offset + ip_len, proto)?;

            let ptr_tuple = OffsetTuple7 {
                src_mac: OffsetEbpfMac { ofs: (src_mac as usize - data) as u16 },
                dst_mac: OffsetEbpfMac { ofs: (dst_mac as usize - data) as u16 },
                src_ip: OffsetEbpfIp { ofs: (src_ip as usize - data) as u16, is_v6: false },
                src_port,
                dst_ip: OffsetEbpfIp { ofs: (dst_ip as usize - data) as u16, is_v6: false },
                dst_port,
                proto: OffsetEbpfProto { ofs: (proto as usize - data) as u16 },
            };

            return Ok((
                ptr_tuple,
                OffsetCsum{
                    l3_check: (l3_csum as usize - data) as u16,
                    l4_check: l4_csum.ofs
                }
            ))
        },
        Ok(EtherType::Ipv6) => {
            let iphdr: *mut Ipv6Hdr = match ptr_mut_at(data, data_end, EthHdr::LEN) {
                Ok(hdr) => hdr,
                Err(_) => return Err(EbpfAction::DROP),
            };

            let src_ip = core::ptr::addr_of_mut!((*iphdr).src_addr);
            let dst_ip = core::ptr::addr_of_mut!((*iphdr).dst_addr);

            let ip_len = Ipv6Hdr::LEN;
            let proto = match (*iphdr).next_hdr() {
                Ok(p) => p,
                Err(_) => {
                    return Err(EbpfAction::DROP)
                }
            };

            let (
                src_port,
                dst_port,
                l4_csum
            ) = try_parse_proto(data, data_end, l3_offset + ip_len, proto)?;

            let ptr_tuple = OffsetTuple7 {
                src_mac: OffsetEbpfMac { ofs: (src_mac as usize - data) as u16 },
                dst_mac: OffsetEbpfMac { ofs: (dst_mac as usize - data) as u16 },
                src_ip: OffsetEbpfIp { ofs: (src_ip as usize - data) as u16, is_v6: true },
                src_port,
                dst_ip: OffsetEbpfIp { ofs: (dst_ip as usize - data) as u16, is_v6: true },
                dst_port,
                proto: OffsetEbpfProto { ofs: (proto as usize - data) as u16 },
            };

            return Ok((
                ptr_tuple,
                OffsetCsum{
                    l3_check: 0,
                    l4_check: l4_csum.ofs
                }
            ))
        },
        _ => {
            return Err(EbpfAction::DROP)
        }
    }

    #[allow(unreachable_code)]
    Err(EbpfAction::DROP)
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn try_parse_proto(
    data: usize,
    data_end: usize,
    offset: usize,
    protocol: IpProto
) -> Result<(OffsetEbpfPort, OffsetEbpfPort, OffsetCsumL), EbpfAction> {
    match protocol {
        IpProto::Tcp => {
            let tcphdr: *mut TcpHdr = match ptr_mut_at(data, data_end, offset) {
                Ok(hdr) => hdr,
                Err(_) => return Err(EbpfAction::DROP),
            };

            let src = core::ptr::addr_of_mut!((*tcphdr).source);
            let dst = core::ptr::addr_of_mut!((*tcphdr).dest);

            let l4_csum = core::ptr::addr_of_mut!((*tcphdr).check);
            
            return Ok((
                OffsetEbpfPort { ofs: (src as usize - data) as u16 },
                OffsetEbpfPort { ofs: (dst as usize - data) as u16 },
                OffsetCsumL { ofs: (l4_csum as usize - data) as u16 }
            ))
        },
        IpProto::Udp => {
            let udphdr: *mut UdpHdr = match ptr_mut_at(data, data_end, offset) {
                Ok(hdr) => hdr,
                Err(_) => return Err(EbpfAction::DROP),
            };

            let src = core::ptr::addr_of_mut!((*udphdr).src);
            let dst = core::ptr::addr_of_mut!((*udphdr).dst);

            let l4_csum = core::ptr::addr_of_mut!((*udphdr).check);
            
            return Ok((
                OffsetEbpfPort { ofs: (src as usize - data) as u16 },
                OffsetEbpfPort { ofs: (dst as usize - data) as u16 },
                OffsetCsumL { ofs: (l4_csum as usize - data) as u16 }
            ))
        },
        _ => {
            return Err(EbpfAction::DROP);
        }
    }

    #[allow(unreachable_code)]
    Err(EbpfAction::DROP)
}

#[inline(always)]
pub fn csum_fold(mut sum: u32) -> u16 {
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    !(sum as u16)
}

#[inline(always)]
pub fn csum_diff4(old: u32, new: u32, mut curr: u32) -> u32 {
    curr += !old & 0xFFFF;
    curr += !old >> 16;
    curr += new & 0xFFFF;
    curr += new >> 16;
    curr
}

#[inline(always)]
pub fn csum_diff2(old: u16, new: u16, mut curr: u32) -> u32 {
    curr += !old as u32;
    curr += new as u32;
    curr
}

#[inline(always)]
pub fn csum_diff16(old: &[u32; 4], new: &[u32; 4], mut curr: u32) -> u32 {
    for i in 0..4 {
        curr += !old[i] & 0xFFFF;
        curr += !old[i] >> 16;

        curr += new[i] & 0xFFFF;
        curr += new[i] >> 16;
    }
    curr
}