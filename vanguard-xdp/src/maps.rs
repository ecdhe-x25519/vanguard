use aya_ebpf::maps::RingBuf;
pub use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruPerCpuHashMap, Array, PerCpuArray, lpm_trie::*},
};

pub use vanguard_core::{
    xdp::maps::{
        config::XdpConfig,
        counter::*,
        rules::{XdpRuleValue, XdpRuleKey}
    },
    common::{
        ip::*,
        maps::{
            blacklist::BlockEvent,
        }
    },
};

#[map]
pub static MAGLEV_POOL: Array<EbpfIp> = Array::<EbpfIp>::with_max_entries(65537, 0);

#[map]
pub static CONFIG: Array<XdpConfig> = Array::<XdpConfig>::with_max_entries(1, 0);

#[map]
pub static BLOCK_EVENT: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
pub static BLACKLIST: LpmTrie<EbpfIp, u8> = LpmTrie::with_max_entries(65536, 0);
#[inline(always)]
pub fn is_blocked(ip: &EbpfIp) -> bool {
    let key: Key<EbpfIp> = Key {
        prefix_len: 32,
        data: *ip,
    };

    BLACKLIST.get(&key).is_some()
}

#[map]
pub static WHITELIST: LpmTrie<EbpfIp, u8> = LpmTrie::with_max_entries(65536, 0); // u8 is nothing
#[inline(always)]
pub fn is_white(ip: &EbpfIp) -> bool {
    let key: Key<EbpfIp> = Key {
        prefix_len: 32,
        data: *ip,
    };

    WHITELIST.get(&key).is_some()
}

#[map]
pub static RULES: HashMap<XdpRuleKey, XdpRuleValue> = HashMap::with_max_entries(1024, 0);

#[map]
pub static PACKET_COUNTER: LruPerCpuHashMap<EbpfIp, XdpPacketCounter> = LruPerCpuHashMap::with_max_entries(65536, 0);
#[inline(always)]
pub fn check_limit(ip: &EbpfIp, now_ns: u64, config: &XdpConfig) -> bool {
    unsafe {
        if let Some(ptr) = PACKET_COUNTER.get_ptr_mut(ip) {
            let cnt = &mut *ptr;

            if now_ns > cnt.last_update {
                let elapsed_ns = now_ns - cnt.last_update;
                let generated_tokens = elapsed_ns / config.interval;
                if generated_tokens > 0 {
                    cnt.tokens = core::cmp::min(config.max_tokens, cnt.tokens + generated_tokens);
                    cnt.last_update += generated_tokens * config.interval;
                }
            } else {
                cnt.last_update = now_ns;
            }

            if cnt.tokens >= 1 {
                cnt.tokens -= 1;
                return true;
            }

            false
        } else {
            let new_state = XdpPacketCounter {
                tokens: config.max_tokens.saturating_sub(1),
                last_update: now_ns,
            };
            let _ = PACKET_COUNTER.insert(ip, new_state, 0);
            true
        }
    }
}

#[map]
pub static STATS: PerCpuArray<GlobalStats> = PerCpuArray::<GlobalStats>::with_max_entries(1, 0);
#[repr(C)]
pub struct GlobalStats {
    pub total: u64,
    pub dropped: u64,
    pub passed: u64,
    pub tx: u64,
    pub redirected: u64,
}
#[inline(always)]
pub fn update_stats(action: u32) {
    let stats = STATS.get_ptr_mut(0);
    if let Some(stats) = stats {
        let stats = unsafe { &mut *stats };
        stats.total += 1;
        match action {
            1 => stats.dropped += 1,
            2 => stats.passed += 1,
            3 => stats.tx += 1,
            4 => stats.redirected += 1,
            _ => {}
        }
    }
}