use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::{TcpHdr},
    udp::UdpHdr,
};

use core::mem;

use crate::common::{
    commons::EbpfAction,
    ip::{EbpfIp, EbpfPort}
};

#[repr(C)]
pub struct OffsetEbpfPort { pub ptr: u16 }

#[repr(C)]
pub struct OffsetEbpfProto { pub ptr: u16 }

#[repr(C)]
pub struct OffsetEbpfMac { pub ptr: u16 }

#[repr(C)]
pub struct OffsetEbpfIp {
    pub ptr: u16,
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
pub struct OffsetCsumL { pub ptr: u16 }

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HeaderUpdates {
    pub src_ip: Option<EbpfIp>,
    pub dst_ip: Option<EbpfIp>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn read_unchecked<T: Copy>(offset: u16, data: usize) -> T {
    let abs_ptr = (data + offset as usize) as *const u8;
    core::ptr::read_unaligned(abs_ptr as *const T)
}

#[inline(always)]
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
pub unsafe fn try_parse_ip<F>(
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
                src_mac: OffsetEbpfMac { ptr: (src_mac as usize - data) as u16 },
                dst_mac: OffsetEbpfMac { ptr: (dst_mac as usize - data) as u16 },
                src_ip: OffsetEbpfIp { ptr: (src_ip as usize - data) as u16, is_v6: false },
                src_port,
                dst_ip: OffsetEbpfIp { ptr: (dst_ip as usize - data) as u16, is_v6: false },
                dst_port,
                proto: OffsetEbpfProto { ptr: (proto as usize - data) as u16 },
            };

            return Ok((
                ptr_tuple,
                OffsetCsum{
                    l3_check: (l3_csum as usize - data) as u16,
                    l4_check: l4_csum.ptr
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
                src_mac: OffsetEbpfMac { ptr: (src_mac as usize - data) as u16 },
                dst_mac: OffsetEbpfMac { ptr: (dst_mac as usize - data) as u16 },
                src_ip: OffsetEbpfIp { ptr: (src_ip as usize - data) as u16, is_v6: true },
                src_port,
                dst_ip: OffsetEbpfIp { ptr: (dst_ip as usize - data) as u16, is_v6: true },
                dst_port,
                proto: OffsetEbpfProto { ptr: (proto as usize - data) as u16 },
            };

            return Ok((
                ptr_tuple,
                OffsetCsum{
                    l3_check: 0,
                    l4_check: l4_csum.ptr
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
                OffsetEbpfPort { ptr: (src as usize - data) as u16 },
                OffsetEbpfPort { ptr: (dst as usize - data) as u16 },
                OffsetCsumL { ptr: (l4_csum as usize - data) as u16 }
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
                OffsetEbpfPort { ptr: (src as usize - data) as u16 },
                OffsetEbpfPort { ptr: (dst as usize - data) as u16 },
                OffsetCsumL { ptr: (l4_csum as usize - data) as u16 }
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
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn swap<T: Copy>(
    src: *mut T,
    dst: *mut T,
) {
    let val_src = core::ptr::read_volatile(src);
    let val_dst = core::ptr::read_volatile(dst);
    
    core::ptr::write_volatile(src, val_dst);
    core::ptr::write_volatile(dst, val_src);
}

#[inline(always)]
fn csum_fold(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[inline(always)]
fn csum_diff_u32(old: u32, new: u32, mut current_sum: u32) -> u32 {
    current_sum += (!old & 0xFFFF) + (!old >> 16);
    current_sum += (new & 0xFFFF) + (new >> 16);
    current_sum
}

#[inline(always)]
fn csum_diff_u16(old: u16, new: u16, mut current_sum: u32) -> u32 {
    current_sum += !old as u32;
    current_sum += new as u32;
    current_sum
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn update_port(data: usize, offset: usize, new_port_be: u16, l4_sum: &mut u32) {
    let ptr = (data + offset) as *mut u16;
    let old_be = core::ptr::read_volatile(ptr);
    if old_be != new_port_be {
        *l4_sum = csum_diff_u16(u16::from_be(old_be), u16::from_be(new_port_be), *l4_sum);
        core::ptr::write_volatile(ptr, new_port_be);
    }
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn update_ipv4(data: usize, offset: usize, new_ip: EbpfIp, l3_sum: &mut u32, l4_sum: &mut u32) {
    let ptr = (data + offset) as *mut u32;
    let old_be = core::ptr::read_volatile(ptr);
    let new_be = u32::from_ne_bytes([new_ip.addr[15], new_ip.addr[14], new_ip.addr[13], new_ip.addr[12]]);
    if old_be != new_be {
        *l3_sum = csum_diff_u32(u32::from_be(old_be), u32::from_be(new_be), *l3_sum);
        *l4_sum = csum_diff_u32(u32::from_be(old_be), u32::from_be(new_be), *l4_sum);
        core::ptr::write_volatile(ptr, new_be);
    }
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn update_ipv6(data: usize, offset: usize, new_ip: EbpfIp, l4_sum: &mut u32) {
    let ptr = (data + offset) as *mut [u32; 4];
    let old_be = core::ptr::read_volatile(ptr);
    let new_be: [u32; 4] = core::mem::transmute(new_ip.addr);
    if old_be != new_be {
        for i in 0..4 {
            let old_word = u32::from_be(old_be[i]);
            let new_word = u32::from_be(new_be[i]);
            if old_word != new_word {
                *l4_sum = csum_diff_u32(old_word, new_word, *l4_sum);
            }
        }
        core::ptr::write_volatile(ptr, new_be);
    }
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn update_net_headers(
    data: usize,
    l3_offset: u16,
    l4_offset: u16,
    is_v6: bool,
    updates: HeaderUpdates,
    offset_csum: OffsetCsum,
) {
    let l4_check_ptr = (data + offset_csum.l4_check as usize) as *mut u16;
    let mut l4_sum = !u16::from_be(core::ptr::read_volatile(l4_check_ptr)) as u32;

    if let Some(src_port) = updates.src_port {
        update_port(data, l4_offset as usize, src_port, &mut l4_sum);
    }
    if let Some(dst_port) = updates.src_port {
        update_port(data, l4_offset as usize + 2, dst_port, &mut l4_sum);
    }

    if !is_v6 {
        let l3_check_ptr = (data + offset_csum.l3_check as usize) as *mut u16;
        let mut l3_sum = !u16::from_be(core::ptr::read_volatile(l3_check_ptr)) as u32;

        if let Some(src_ip) = updates.src_ip {
            update_ipv4(data, l3_offset as usize + 12, src_ip, &mut l3_sum, &mut l4_sum);
        }
        if let Some(dst_ip) = updates.dst_ip {
            update_ipv4(data, l3_offset as usize + 16, dst_ip, &mut l3_sum, &mut l4_sum);
        }

        core::ptr::write_volatile(l3_check_ptr, u16::to_be(csum_fold(l3_sum)));
    } else {
        if let Some(src_ip) = updates.src_ip {
            update_ipv6(data, l3_offset as usize + 12, src_ip, &mut l4_sum);
        }
        if let Some(dst_ip) = updates.dst_ip {
            update_ipv6(data, l3_offset as usize + 16, dst_ip, &mut l4_sum);
        }
    }

    core::ptr::write_volatile(l4_check_ptr, u16::to_be(csum_fold(l4_sum)));
}