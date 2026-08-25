use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::{TcpHdr},
    udp::UdpHdr,
};

use core::mem;

use crate::common::{
    ip::*,
    commons::EbpfAction,
};

#[repr(C)]
pub struct OffsetEbpfPort(pub u16);

#[repr(C)]
pub struct OffsetEbpfProto(pub u16);

#[repr(C)]
pub struct OffsetEbpfMac(pub u16);

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
pub struct OffsetCsumL(pub u16);

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
            ) = try_parse_proto(data, data_end, ip_len, proto)?;

            let ptr_tuple = OffsetTuple7 {
                src_mac: OffsetEbpfMac((src_mac as usize - data) as u16),
                dst_mac: OffsetEbpfMac((dst_mac as usize - data) as u16),
                src_ip: OffsetEbpfIp { ptr: (src_ip as usize - data) as u16, is_v6: false },
                src_port: OffsetEbpfPort((src_port.0 as usize - data) as u16),
                dst_ip: OffsetEbpfIp { ptr: (dst_ip as usize - data) as u16, is_v6: false },
                dst_port: OffsetEbpfPort((dst_port.0 as usize - data) as u16),
                proto: OffsetEbpfProto(proto as u16),
            };

            return Ok((
                ptr_tuple,
                OffsetCsum{
                    l3_check: l3_csum as u16,
                    l4_check: l4_csum.0
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

            let (src_port, dst_port, l4_csum) = try_parse_proto(data, data_end, ip_len, proto)?;

            let ptr_tuple = OffsetTuple7 {
                src_mac: OffsetEbpfMac((src_mac as usize - data) as u16),
                dst_mac: OffsetEbpfMac((dst_mac as usize - data) as u16),
                src_ip: OffsetEbpfIp { ptr: (src_ip as usize - data) as u16, is_v6: true },
                src_port: OffsetEbpfPort((src_port.0 as usize - data) as u16),
                dst_ip: OffsetEbpfIp { ptr: (dst_ip as usize - data) as u16, is_v6: true },
                dst_port: OffsetEbpfPort((dst_port.0 as usize - data) as u16),
                proto: OffsetEbpfProto(proto as u16),
            };

            return Ok((
                ptr_tuple,
                OffsetCsum{
                    l3_check: 0,
                    l4_check: l4_csum.0
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
            let tcphdr: *mut TcpHdr = match ptr_mut_at(data, data_end, TcpHdr::LEN + offset) {
                Ok(hdr) => hdr,
                Err(_) => return Err(EbpfAction::DROP),
            };

            let src = core::ptr::addr_of_mut!((*tcphdr).source);
            let dst = core::ptr::addr_of_mut!((*tcphdr).dest);

            let l4_csum = core::ptr::addr_of_mut!((*tcphdr).check);
            
            return Ok((
                OffsetEbpfPort( src as u16 ),
                OffsetEbpfPort( dst as u16 ),
                OffsetCsumL(l4_csum as u16)
            ))
        },
        IpProto::Udp => {
            let udphdr: *mut UdpHdr = match ptr_mut_at(data, data_end, UdpHdr::LEN + offset) {
                Ok(hdr) => hdr,
                Err(_) => return Err(EbpfAction::DROP),
            };

            let src = core::ptr::addr_of_mut!((*udphdr).src);
            let dst = core::ptr::addr_of_mut!((*udphdr).dst);

            let l4_csum = core::ptr::addr_of_mut!((*udphdr).check);
            
            return Ok((
                OffsetEbpfPort( src as u16 ),
                OffsetEbpfPort( dst as u16 ),
                OffsetCsumL(l4_csum as u16)
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
    let tmp = core::ptr::read_volatile(src);
    core::ptr::write_volatile(src, core::ptr::read_volatile(dst));
    core::ptr::write_volatile(dst, tmp);
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

// #[inline(always)]
// #[allow(unsafe_op_in_unsafe_fn)]
// pub unsafe fn update_dst_ipv_checksums(
//     data: usize,
//     dst_ip_offset: u16,
//     new_ip: EbpfIp,
//     offset_csum: OffsetCsum,
//     // Смещение до поля check в IPv4 (l3_offset + 10)
//     // Смещение до поля check в TCP (l4_offset + 16) или UDP (l4_offset + 6)
// ) {
//     let l4_check_ptr = (data + offset_csum.l4_check as usize) as *mut u16;
//     let mut l4_sum = !u16::from_be(core::ptr::read_volatile(l4_check_ptr)) as u32;

//     if !new_ip.is_v6 {
//         let ip_ptr = (data + dst_ip_offset as usize) as *mut u32;
//         let old_ipv4_be = core::ptr::read_volatile(ip_ptr);

//         let new_ipv4_be = unsafe { 
//             let mut tmp = [0u8; 4];
//             tmp.copy_from_slice(&new_ip.in6_u[0..4]);
//             core::mem::transmute::<[u8; 4], u32>(tmp)
//         };

//         if old_ipv4_be == new_ipv4_be { return; }

//         core::ptr::write_volatile(ip_ptr, new_ipv4_be);

//         let l3_check_ptr = (data + offset_csum.l3_check as usize) as *mut u16;
//         let l3_old_sum = !u16::from_be(core::ptr::read_volatile(l3_check_ptr)) as u32;
//         let l3_new_sum = csum_diff_u32(u32::from_be(old_ipv4_be), u32::from_be(new_ipv4_be), l3_old_sum);
//         core::ptr::write_volatile(l3_check_ptr, u16::to_be(csum_fold(l3_new_sum)));

//         l4_sum = csum_diff_u32(u32::from_be(old_ipv4_be), u32::from_be(new_ipv4_be), l4_sum);
//         core::ptr::write_volatile(l4_check_ptr, u16::to_be(csum_fold(l4_sum)));

//     } else {
//         let ip_ptr = (data + dst_ip_offset as usize) as *mut [u32; 4];
//         let old_ipv6_be = core::ptr::read_volatile(ip_ptr);

//         let new_ipv6_be: [u32; 4] = unsafe { core::mem::transmute(new_ip.in6_u) };

//         if old_ipv6_be == new_ipv6_be { return; }

//         for i in 0..4 {
//             let old_word = u32::from_be(old_ipv6_be[i]);
//             let new_word = u32::from_be(new_ipv6_be[i]);
//             if old_word != new_word {
//                 l4_sum = csum_diff_u32(old_word, new_word, l4_sum);
//             }
//         }

//         core::ptr::write_volatile(ip_ptr, new_ipv6_be);
//         core::ptr::write_volatile(l4_check_ptr, u16::to_be(csum_fold(l4_sum)));
//     }
// }