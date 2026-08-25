use aya_ebpf::{
    bindings::xdp_action,
    programs::XdpContext,
};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{
        IpProto,
        Ipv4Hdr,
        Ipv6Hdr
    },
    tcp::{TCP_HDR_LEN, TcpHdr},
    udp::UdpHdr,
};
use vanguard_core::xdp::maps::rules::XdpRuleAction;

use core::mem;

#[inline(always)]
pub fn ptr_at<T>(
    ctx: &XdpContext,
    offset: usize
) -> Result<*mut T, ()> {
    let (start, end) = (ctx.data(), ctx.data_end());
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *mut T;
    Ok(ptr)
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn try_parse_ip(
    ctx: &XdpContext,
    offset: usize
) -> Result<(EbpfIp, u32), u32> {
    let ethhdr: *mut EthHdr = match ptr_at(ctx, offset) {
        Ok(hdr) => hdr,
        Err(_) => return Err(xdp_action::XDP_DROP),
    };

    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {
            let iphdr: *mut Ipv4Hdr = match ptr_at(ctx, EthHdr::LEN) {
                Ok(hdr) => hdr,
                Err(_) => return Err(xdp_action::XDP_DROP),
            };

            let src = core::ptr::addr_of_mut!((*iphdr).src_addr);
            let dst = core::ptr::addr_of_mut!((*iphdr).dst_addr);

            let ip_len = (*iphdr).ihl() as usize * 4;
            let proto = match (*iphdr).proto() {
                Ok(p) => p,
                Err(_) => {
                    return Err(xdp_action::XDP_DROP)
                }
            };

            let (srcp, dstp) = try_parse_proto(ctx, ip_len, proto)?;

            let key = XdpRuleKey {
                ip: EbpfIp::from_v4(*(src)),
                port: EbpfPort(u16::from_be_bytes(*(dstp))),
                eth: EtherType::Ipv4,
                proto,
            };

            if let Some(val) = RULES.get(key) {
                match val.action {
                    XdpRuleAction::TX => {
                        core::ptr::swap(src, dst);
                        core::ptr::swap(srcp, dstp);
                    }
                    XdpRuleAction::REDIRECT => {
                        let redir = val.redirect;

                        let new_dst_ip = u32::to_be_bytes(redir.ip.0[3]);
                        let new_dst_port = u16::to_be_bytes(redir.port.0);

                        core::ptr::swap(src, dst);
                        core::ptr::swap(srcp, dstp);

                        core::ptr::write_volatile(dst, new_dst_ip);
                        core::ptr::write_volatile(dstp, new_dst_port);
                    }
                    _ => {}
                }
                
                return Ok((key.ip, val.action as u32));
            }

            return Ok((key.ip, xdp_action::XDP_PASS))
        },
        Ok(EtherType::Ipv6) => {
            let iphdr: *mut Ipv6Hdr = match ptr_at(ctx, EthHdr::LEN) {
                Ok(hdr) => hdr,
                Err(_) => return Err(xdp_action::XDP_DROP),
            };

            let src = core::ptr::addr_of_mut!((*iphdr).src_addr);
            let dst = core::ptr::addr_of_mut!((*iphdr).dst_addr);

            let ip_len = Ipv6Hdr::LEN;
            let proto = match (*iphdr).next_hdr() {
                Ok(p) => p,
                Err(_) => {
                    return Err(xdp_action::XDP_DROP)
                }
            };

            let (srcp, dstp) = try_parse_proto(ctx, ip_len, proto)?;

            let key = XdpRuleKey {
                ip: EbpfIp::from_v6(core::mem::transmute::<[u8; 16], [u32; 4]>(*(src))),
                port: EbpfPort(u16::from_be_bytes(*(dstp))),
                eth: EtherType::Ipv4,
                proto,
            };

            if let Some(val) = RULES.get(key) {
                match val.action {
                    XdpRuleAction::TX => {
                        core::ptr::swap(src, dst);
                        core::ptr::swap(srcp, dstp);
                    }
                    XdpRuleAction::REDIRECT => {
                        let redir = val.redirect;
                        let new_dst_ip = core::mem::transmute::<[u32; 4], [u8; 16]>(redir.ip.0);
                        let new_dst_port = u16::to_be_bytes(redir.port.0);

                        core::ptr::swap(src, dst);
                        core::ptr::swap(srcp, dstp);

                        core::ptr::write_volatile(dst, new_dst_ip);
                        core::ptr::write_volatile(dstp, new_dst_port);
                    }
                    _ => {}
                }

                return Ok((key.ip, val.action as u32));
            }

            return Ok((key.ip, xdp_action::XDP_PASS))
        },
        _ => {
            return Err(xdp_action::XDP_PASS)
        }
    }

    #[allow(unreachable_code)]
    Err(xdp_action::XDP_PASS)
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn try_parse_proto(
    ctx: &XdpContext,
    offset: usize,
    protocol: IpProto
) -> Result<(*mut [u8; 2], *mut [u8; 2]), u32> {
    match protocol {
        IpProto::Tcp => {
            let tcphdr: *mut TcpHdr = match ptr_at(ctx, TCP_HDR_LEN + offset) {
                Ok(hdr) => hdr,
                Err(_) => return Err(xdp_action::XDP_DROP),
            };

            let src = core::ptr::addr_of_mut!((*tcphdr).source);
            let dst = core::ptr::addr_of_mut!((*tcphdr).dest);
            
            return Ok((src, dst))
        },
        IpProto::Udp => {
            let udphdr: *mut UdpHdr = match ptr_at(ctx, UdpHdr::LEN + offset) {
                Ok(hdr) => hdr,
                Err(_) => return Err(xdp_action::XDP_DROP),
            };

            let src = core::ptr::addr_of_mut!((*udphdr).src);
            let dst = core::ptr::addr_of_mut!((*udphdr).dst);
            
            return Ok((src, dst))
        },
        _ => {
            return Err(xdp_action::XDP_PASS);
        }
    }

    #[allow(unreachable_code)]
    Err(xdp_action::XDP_PASS)
}