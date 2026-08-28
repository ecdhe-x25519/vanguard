#[cfg(feature = "userspace")]
use super::*;

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct TcRuleKey(Tuple5);
#[cfg(feature = "userspace")]
unsafe impl Pod for TcRuleKey {}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct TcRuleValue {
    pub redirect: TcRuleKey,
    pub action: EbpfAction,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for TcRuleValue {}

#[cfg(feature = "userspace")]
pub struct TcRulesMap;

#[cfg(feature = "userspace")]
impl TcRulesMap {
    pub fn get(bpf: &mut Ebpf) -> Result<HashMap<MapData, TcRuleKey, TcRuleValue>, VanguardError> {
        get_map!(bpf, "RULES", HashMap, HashMap<MapData, TcRuleKey, TcRuleValue>)
    }

    pub fn add(bpf: &mut Ebpf, key: TcRuleKey, value: TcRuleValue) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;

        map.insert(key, value, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        Ok(())
    }

    pub fn remove(bpf: &mut Ebpf, key: TcRuleKey) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;

        map.remove(&key)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;

        Ok(())
    }
}