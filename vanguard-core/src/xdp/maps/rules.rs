#[cfg(feature = "userspace")]
use super::*;

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct XdpRuleKey{ pub inner: Tuple5 }
#[cfg(feature = "userspace")]
unsafe impl Pod for XdpRuleKey {}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub enum XdpRuleValue {
    Drop,
    Pass,
    Tx {
        backends: [u32; 16],
        encap: bool,
    },
    Redirect {
        target_ifindex: u32,
        target_mac: [u8; 6],
    },
}
#[cfg(feature = "userspace")]
unsafe impl Pod for XdpRuleValue {}

#[cfg(feature = "userspace")]
pub struct XdpRulesMap;

#[cfg(feature = "userspace")]
impl XdpRulesMap {
    pub fn get(bpf: &mut Ebpf) -> Result<HashMap<MapData, XdpRuleKey, XdpRuleValue>, VanguardError> {
        get_map!(bpf, "RULES", HashMap, HashMap<MapData, XdpRuleKey, XdpRuleValue>)
    }

    pub fn add(bpf: &mut Ebpf, key: XdpRuleKey, value: XdpRuleValue) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;

        map.insert(key, value, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        Ok(())
    }

    pub fn remove(bpf: &mut Ebpf, key: XdpRuleKey) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;

        map.remove(&key)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;

        Ok(())
    }
}