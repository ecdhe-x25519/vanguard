#![no_std]
#![no_main]

mod parse;
mod maps;

use aya_ebpf::{
    helpers::bpf_ktime_get_coarse_ns,
    macros::xdp,
    programs::xdp::XdpContext,
};
use vanguard_core::common::commons::EbpfAction;

use crate::maps::*;

#[xdp]
pub fn main(ctx: XdpContext) -> u32 {
    match unsafe { try_filter(ctx) } {
        Ok(ret) => {
            let ret = ret.to_xdp();
            update_stats(ret);
            ret
        }
        Err(ret) => {
            let ret = ret.to_xdp();
            update_stats(ret);
            ret
        },
    }
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn try_filter(ctx: XdpContext) -> Result<EbpfAction, EbpfAction> {
    let (addr, action) = parse::try_filter_ip(&ctx, 0)?;

    if maps::is_white(&addr) {
        return Ok(action)
    }
    
    let xdp_config = if let Some(ptr) = CONFIG.get_ptr(0) {
        &*ptr
    } else {
        return Err(EbpfAction::PASS);
    };

    let now = bpf_ktime_get_coarse_ns();

    if maps::is_blocked(&addr) {
        return Err(EbpfAction::DROP);
    } else if !maps::check_limit(&addr, now, xdp_config) {
        if let Some(mut buf) = maps::BLOCK_EVENT.reserve::<BlockEvent>(0) {
            let event = &mut *buf.as_mut_ptr();
            event.ip = EbpfNet { ip: addr, prefix_len: 32 };
            buf.submit(0);
        }
        return Err(EbpfAction::DROP)
    }

    Ok(action)
}