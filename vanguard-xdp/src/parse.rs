use aya_ebpf::programs::XdpContext;

use vanguard_core::{
    common::{
        commons::{EbpfAction, Tuple5}, packet::*,
    }, xdp::maps::rules::XdpRuleKey,
};

use crate::maps::*;

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn try_filter_ip(
    ctx: &XdpContext,
    offset: usize
) -> Result<(EbpfIp, EbpfAction), EbpfAction> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let (tuple, csum) = try_parse_ip(
        data,
        data_end,
        offset,
    )?;

    let key = XdpRuleKey(Tuple5 {
        src_ip: read_unchecked(tuple.src_ip.ptr, data),
        src_port: read_unchecked(tuple.src_port.ptr, data),
        dst_ip: read_unchecked(tuple.dst_ip.ptr, data),
        dst_port: read_unchecked(tuple.dst_port.ptr, data),
        proto: read_unchecked(tuple.proto.ptr, data),
    });

    if let Some(val) = RULES.get(&key) {
        let data_ptr = data as *mut u8;

        let src_mac_ptr = data_ptr.add(tuple.src_mac.ptr as usize) as *mut [u8; 6];
        let dst_mac_ptr = data_ptr.add(tuple.dst_mac.ptr as usize) as *mut [u8; 6];
        
        let src_port_ptr = data_ptr.add(tuple.src_port.ptr as usize) as *mut u16;
        let dst_port_ptr = data_ptr.add(tuple.dst_port.ptr as usize) as *mut u16;

        match val.action {
            EbpfAction::TX => {
                swap(src_mac_ptr, dst_mac_ptr);
                swap(src_port_ptr, dst_port_ptr);

                if !tuple.src_ip.is_v6 {
                    let src_ip_ptr = data_ptr.add(tuple.src_ip.ptr as usize) as *mut u32;
                    let dst_ip_ptr = data_ptr.add(tuple.dst_ip.ptr as usize) as *mut u32;
                    swap(src_ip_ptr, dst_ip_ptr);
                } else {
                    let src_ip_ptr = data_ptr.add(tuple.src_ip.ptr as usize) as *mut [u32; 4];
                    let dst_ip_ptr = data_ptr.add(tuple.dst_ip.ptr as usize) as *mut [u32; 4];
                    swap(src_ip_ptr, dst_ip_ptr);
                }
            }
            EbpfAction::REDIRECT => {
                let redir = val.redirect.0;

                swap(src_mac_ptr, dst_mac_ptr);
                swap(src_port_ptr, dst_port_ptr);

                if !tuple.src_ip.is_v6 {
                    let src_ip_ptr = data_ptr.add(tuple.src_ip.ptr as usize) as *mut u32;
                    let dst_ip_ptr = data_ptr.add(tuple.dst_ip.ptr as usize) as *mut u32;

                    swap(src_ip_ptr, dst_ip_ptr);

                    let new_dst_ip_be = redir.src_ip; 
                    let new_dst_port_be = u16::to_be(redir.src_port.0);
                    let new_dst_port_be = u16::from_be_bytes(redir.src_port.0);

                    let target_ip = EbpfIp::from_v4(new_dst_ip_be);
                    update_ip_checksums(
                        data,
                        tuple.dst_ip.ptr,
                        csum.l3_check,
                        csum.l4_check,
                        target_ip,
                    );

                    core::ptr::write_volatile(dst_port_ptr, new_dst_port_be);
                } else {
                    let src_ip_ptr = data_ptr.add(tuple.src_ip.ptr as usize) as *mut [u32; 4];
                    let dst_ip_ptr = data_ptr.add(tuple.dst_ip.ptr as usize) as *mut [u32; 4];

                    swap(src_ip_ptr, dst_ip_ptr);

                    let new_dst_ip_be = redir.src_ip;
                    let new_dst_port_be = u16::to_be(redir.src_port);
                    let new_dst_port_be = u16::from_be_bytes(redir.src_port.0);

                    let target_ip = EbpfIp::from_v6(new_dst_ip_be);
                    update_ip_checksums(
                        data,
                        tuple.dst_ip.ptr,
                        0,
                        csum.l4_check,
                        target_ip,
                    );

                    core::ptr::write_volatile(dst_port_ptr, new_dst_port_be);
                }
            }
            _ => {}
        }

        return Ok((key.0.src_ip, val.action));
    }
    
    return Ok((key.0.src_ip, EbpfAction::DROP))
}