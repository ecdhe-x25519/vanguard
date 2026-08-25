#![no_std]
#![no_main]

mod parse;

use aya_ebpf::{
    EbpfContext,
    bindings::*,
    helpers::bpf_ktime_get_coarse_ns,
    macros::classifier,
    programs::TcContext,
};

#[classifier]
pub fn main(ctx: TcContext) -> i32 {
    match unsafe { try_filter(ctx) } {
        Ok(ret) => {
            update_stats(ret);
            ret
        }
        Err(_) => {
            update_stats(2);
            TC_ACT_SHOT
        },
    }
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn try_filter(ctx: TcContext) -> Result<i32, i32> {
    let skb_ptr = ctx.as_ptr() as *mut __sk_buff;

    if (*skb_ptr).ingress_ifindex == 0 {
        try_egress(ctx);
    }

    try_ingress(ctx);


}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn try_ingress(ctx: TcContext) -> Result<i32, i32> {

}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn try_egress(ctx: TcContext) -> Result<i32, i32> {
    
}