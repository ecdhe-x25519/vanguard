#[cfg(feature = "userspace")]
use super::*;

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct SkbRuleKey(Tuple5);
#[cfg(feature = "userspace")]
unsafe impl Pod for SkbRuleKey {}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct SkbRuleValue {
    pub redirect: SkbRuleKey,
    pub action: EbpfAction,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for SkbRuleValue {}

#[cfg(feature = "userspace")]
pub struct XdpRulesMap;

#[cfg(feature = "userspace")]
impl XdpRulesMap {
    pub fn get(bpf: &mut Ebpf) -> Result<HashMap<MapData, SkbRuleKey, SkbRuleValue>, VanguardError> {
        get_map!(bpf, "RULES", HashMap, HashMap<MapData, SkbRuleKey, SkbRuleValue>)
    }

    pub fn add(bpf: &mut Ebpf, key: SkbRuleKey, value: SkbRuleValue) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;

        map.insert(key, value, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        Ok(())
    }

    pub fn remove(bpf: &mut Ebpf, key: SkbRuleKey) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;

        map.remove(&key)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;

        Ok(())
    }
}