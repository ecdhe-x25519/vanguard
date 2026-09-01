use aya_ebpf::{
    programs::XdpContext,
    helpers::bpf_redirect,
};

use vanguard_core::{
    common::{
        commons::{EbpfAction, Tuple5},
        packet::*,
    },
    xdp::maps::rules::XdpRuleKey,
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

    let key;

    if tuple.src_ip.is_v6 {
        key = XdpRuleKey{ inner: Tuple5 {
            src_ip: EbpfIp { addr: read_offset::<[u8; 16]>(data, tuple.src_ip.ofs), is_v6: true },
            src_port: EbpfPort { inner: read_offset(data, tuple.src_port.ofs) },
            dst_ip: EbpfIp { addr: read_offset::<[u8; 16]>(data, tuple.dst_ip.ofs), is_v6: true },
            dst_port: EbpfPort { inner: read_offset(data, tuple.dst_port.ofs) },
            proto: EbpfProto { inner: read_offset(data, tuple.proto.ofs) },
        }};
    } else {
        let src_ip_v4 = read_offset::<[u8; 4]>(data, tuple.src_ip.ofs);
        let mut src_ip_16 = [0u8; 16];
        src_ip_16[..4].copy_from_slice(&src_ip_v4);

        let dst_ip_v4 = read_offset::<[u8; 4]>(data, tuple.dst_ip.ofs);
        let mut dst_ip_16 = [0u8; 16];
        dst_ip_16[..4].copy_from_slice(&dst_ip_v4);

        key = XdpRuleKey{ inner: Tuple5 {
            src_ip: EbpfIp { addr: src_ip_16, is_v6: false },
            src_port: EbpfPort { inner: read_offset(data, tuple.src_port.ofs) },
            dst_ip: EbpfIp { addr: dst_ip_16, is_v6: false },
            dst_port: EbpfPort { inner: read_offset(data, tuple.dst_port.ofs) },
            proto: EbpfProto { inner: read_offset(data, tuple.proto.ofs) },
        }};
    }

    if let Some(val) = RULES.get(&key) {
        match val.action {
            EbpfAction::TX => handle_tx(data, data_end, tuple, csum),
            EbpfAction::REDIRECT => handle_redirect(data, data_end, tuple, val.redirect, csum),
            other => return Ok((key.inner.src_ip, other)),
        };
    }
    
    return Ok((key.inner.src_ip, EbpfAction::DROP))
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn handle_tx(
    data: usize,
    data_end: usize,
    tuple: OffsetTuple7,
    csum: OffsetCsum,
) -> Result<(), EbpfAction> {
    swap_offset::<[u8; 6]>(data, tuple.src_mac.ofs, tuple.dst_mac.ofs);
    swap_offset::<u16>(data, tuple.src_port.ofs, tuple.dst_port.ofs);

    if !tuple.src_ip.is_v6 {
        swap_offset::<u32>(data, tuple.src_ip.ofs, tuple.dst_ip.ofs);
    } else {
        swap_offset::<[u32; 4]>(data, tuple.src_ip.ofs, tuple.dst_ip.ofs);
    }
    
    Ok(())
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn handle_redirect(
    data: usize, 
    data_end: usize, 
    tuple: OffsetTuple7,
    redir: XdpRuleKey,
) -> Result<(), EbpfAction> {
    bpf_redirect(ifindex, 0)
}