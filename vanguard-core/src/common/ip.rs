#[cfg(feature = "userspace")]
use super::commons::*;

#[cfg(feature = "userspace")]
use crate::error::VanguardError;

use std::net::*;
use std::str::FromStr;

#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct EbpfPort { pub inner: [u8; 2] }

#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct EbpfProto { pub inner: u8 }

#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct EbpfMac { pub inner: [u8; 6] }

#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct EbpfIp {
    pub addr: [u8; 16],
    pub is_v6: bool,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for EbpfIp {}

impl EbpfIp {
    
}

#[cfg(feature = "userspace")]
impl Parse for EbpfIp {
    fn as_str(&self) -> Result<String, VanguardError> {
        if !self.is_v6 {
            let octets: [u8; 4] = self.addr[0..4]
                .try_into()
                .map_err(|_| VanguardError::IoError("failed to slice IPv4 bytes"))?;
            Ok(Ipv4Addr::from(octets).to_string())
        } else {
            Ok(Ipv6Addr::from(self.addr).to_string())
        }
    }

    fn to_type(s: String) -> Result<Self, VanguardError> {
        let ip = IpAddr::from_str(s.trim())
            .map_err(|_| VanguardError::IoError("invalid IP"))?;

        match ip {
            IpAddr::V4(v4) => {
                let mut addr = [0u8; 16];
                addr[0..4].copy_from_slice(&v4.octets());
                
                Ok(Self {
                    addr,
                    is_v6: false,
                })
            }
            IpAddr::V6(v6) => Ok(Self {
                addr: v6.octets(),
                is_v6: true,
            }),
        }
    }
}

#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct EbpfNet {
    pub ip: EbpfIp,
    pub prefix_len: u32,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for EbpfNet {}

use std::net::Ipv6Addr;

#[cfg(feature = "userspace")]
impl Parse for EbpfNet {
    fn as_str(&self) -> Result<String, VanguardError> {
        let ip_str = self.ip.as_str()?;
        Ok(format!("{}/{}", ip_str, self.prefix_len))
    }

    fn to_type(s: String) -> Result<Self, VanguardError> {
        let s = s.trim();
        let (ip_str, prefix_str) = s.split_once('/').unwrap_or((s, ""));

        let ip_addr = EbpfIp::to_type(ip_str.to_string())?;

        let raw_prefix = if prefix_str.is_empty() {
            if ip_addr.is_v6 { 128 } else { 32 }
        } else {
            prefix_str.parse::<u32>().map_err(|_| VanguardError::IoError("invalid CIDR prefix"))?
        };

        if ip_addr.is_v6 && raw_prefix > 128 { return Err(VanguardError::IoError("IPv6 prefix cant be > 128")); }
        if !ip_addr.is_v6 && raw_prefix > 32 { return Err(VanguardError::IoError("IPv4 prefix cant be > 32")); }

        let ebpf_net = if ip_addr.is_v6 {
            let ip_v6 = Ipv6Addr::from(ip_addr.addr);
            let mut segments = ip_v6.segments();

            for (i, segment) in segments.iter_mut().enumerate() {
                let bit_floor = (i * 16) as u32;
                if raw_prefix <= bit_floor {
                    *segment = 0;
                } else if raw_prefix < bit_floor + 16 {
                    let rem_bits = raw_prefix - bit_floor;
                    let mask = !0u16 << (16 - rem_bits);
                    *segment &= mask;
                }
            }

            let masked_ip = Ipv6Addr::from(segments);
            EbpfNet {
                ip: EbpfIp {
                    addr: masked_ip.octets(),
                    is_v6: true,
                },
                prefix_len: raw_prefix,
            }
        } else {
            let mask = if raw_prefix == 0 { 0 } else { !0u32 << (32 - raw_prefix) };
            
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&ip_addr.addr[0..4]);
            
            let v4_u32 = u32::from_be_bytes(octets);
            let masked_ip = v4_u32 & mask;
            
            let mut final_addr = [0u8; 16];
            final_addr[0..4].copy_from_slice(&masked_ip.to_be_bytes());

            EbpfNet {
                ip: EbpfIp {
                    addr: final_addr,
                    is_v6: false,
                },
                prefix_len: raw_prefix,
            }
        };

        Ok(ebpf_net)
    }
}

#[cfg(test)]
mod test_ip {
    use super::*;

    #[test]
    fn test_ipv4_conversion() {
        let ip_str = "192.168.1.1".to_string();
        let ip = EbpfIp::to_type(ip_str).unwrap();
        assert_eq!(ip.as_str().unwrap(), "192.168.1.1");
    }

    #[test]
    fn test_ipv6_conversion() {
        let ip_str = "2001:db8::1".to_string();        
        let ip = EbpfIp::to_type(ip_str).unwrap();
        assert_eq!(ip.as_str().unwrap(), "2001:db8::1");
    }

    #[test]
    fn test_trim_whitespace() {
        let ip_str = "  10.0.0.5 \n".to_string();
        let ip = EbpfIp::to_type(ip_str).unwrap();
        assert_eq!(ip.as_str().unwrap(), "10.0.0.5");
    }

    #[test]
    fn test_invalid_ip_format() {
        let bad_ip = "192.168.1.256".to_string();
        assert!(EbpfIp::to_type(bad_ip).is_err());

        let text = "not-an-ip".to_string();
        assert!(EbpfIp::to_type(text).is_err());
        
        let with_port = "127.0.0.1:8080".to_string();
        assert!(EbpfIp::to_type(with_port).is_err());
    }
}

#[cfg(test)]
mod test_net {
    use super::*;

    #[test]
    fn test_ipv4_cidr_round_trip() {
        let net = EbpfNet::to_type("192.168.1.0/24".to_string()).unwrap();
        assert_eq!(net.ip.as_str().unwrap(), "192.168.1.0");
        assert_eq!(net.as_str().unwrap(), "192.168.1.0/24");
        assert_eq!(net.prefix_len, 24);
    }

    #[test]
    fn test_ipv6_cidr_round_trip() {
        let net = EbpfNet::to_type("2001:db8::/64".to_string()).unwrap();
        assert_eq!(net.ip.as_str().unwrap(), "2001:db8::");
        assert_eq!(net.as_str().unwrap(), "2001:db8::/64");
        assert_eq!(net.prefix_len, 64);
    }

    #[test]
    fn test_default_prefix_for_ip_without_cidr() {
        let v4 = EbpfNet::to_type("10.0.0.5".to_string()).unwrap();
        assert_eq!(v4.as_str().unwrap(), "10.0.0.5/32");
        assert_eq!(v4.prefix_len, 32);

        let v6 = EbpfNet::to_type("2001:db8::".to_string()).unwrap();
        assert_eq!(v6.as_str().unwrap(), "2001:db8::/128");
        assert_eq!(v6.prefix_len, 128);
    }

    #[test]
    fn test_invalid_prefix_is_rejected() {
        assert!(EbpfNet::to_type("192.168.1.0/33".to_string()).is_err());
        assert!(EbpfNet::to_type("2001:db8::/129".to_string()).is_err());
        assert!(EbpfNet::to_type("10.0.0.0/prefix".to_string()).is_err());
    }
}