#[cfg(feature = "userspace")]
use super::*;

#[cfg(feature = "userspace")]
pub struct ConnMap {
    map: HashMap<MapData, Tuple5, Tuple5>,
}

#[cfg(feature = "userspace")]
impl ConnMap {
    pub fn get(bpf: &mut Ebpf) -> Result<Self, VanguardError> {
        let map = get_map!(bpf, "CONNTRACK", LruHashMap, HashMap<MapData, Tuple5, Tuple5>)?;
        Ok(Self { map })
    }
}