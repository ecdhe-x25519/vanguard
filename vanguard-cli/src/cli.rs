use clap::{
    Parser,
    Subcommand,
    Args
};

use vanguard_core::{
    xdp::maps::{
        rules::*,
    },
    common::{
        commons::*,
        ip::*
    }
};

use vanguard_grpc::client::VanguardGrpcClient;

use erret_result::*;

#[derive(Parser)]
#[command(name = "vanguard")]
#[command(about = "XDP-based firewall", long_about)]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}
impl Cli {
    pub async fn exec_cmd() ->  ErrResult<()> {
        let cli = Cli::parse();

        if let Some(cmd) = cli.command {
            cmd.handle_cmd().await?;
        };

        Ok(())
    }
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "XDP rules commands", long_about)]
    #[command(subcommand)]
    Rules(RulesCommands),

    #[command(about = "Black or whitelist IP", long_about)]
    #[command(subcommand)]
    Lists(ListsCommands),

    #[command(about = "XDP global stats", long_about)]
    Stats,
}
impl Commands {
    pub async fn handle_cmd(self) -> ErrResult<()> {
        match self {
            Self::Rules(cmd) => {
                RulesCommands::handle(cmd).await?;
            }
            Self::Stats => {
                Self::show_stats().await?;
            }
            Self::Lists(cmd) => {
                ListsCommands::handle(cmd).await?;
            }
        }

        Ok(())
    }

    async fn show_stats() -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;
        let stats = grpc.get_stats().await?;

        println!();
        println!("VANGUARD PACKET STATS:");
        println!("  total: {}", stats.total);
        println!("  dropped: {}", stats.dropped);
        println!("  passed: {}", stats.passed);
        println!("  tx: {}", stats.tx);
        println!("  redirected: {}", stats.redirected);
        println!();

        Ok(())
    }
}

#[derive(Subcommand)]
pub enum ListsCommands {
    #[command(subcommand)]
    Blacklist(BlacklistCommands),

    #[command(subcommand)]
    Whitelist(WhitelistCommands),
}
impl ListsCommands {
    pub async fn handle(self) -> ErrResult<()> {
        match self {
            Self::Blacklist( cmd ) => {
                BlacklistCommands::handle(cmd).await?;
            }
            Self::Whitelist( cmd ) => {
                WhitelistCommands::handle(cmd).await?;
            }
        }

        Ok(())
    }
}

#[derive(Subcommand)]
pub enum BlacklistCommands {
    #[command(about = "Add to XDP blacklist", long_about)]
    Block {
        ip: String,
        until: u64,
    },

    #[command(about = "Delete from XDP blacklist", long_about)]
    Del {
        ip: String,
    },
}
impl BlacklistCommands {
    pub async fn handle(self) -> ErrResult<()> {
        match self {
            Self::Block { ip, until } => {
                Self::block(ip, until).await?;
            }
            Self::Del { ip } => {
                Self::delete(ip).await?;
            }
        }

        Ok(())
    }

    async fn block(ip: String, blocked_until: u64) -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;
        grpc.block(ip, blocked_until).await?;
        Ok(())
    }

    async fn delete(ip: String) -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;
        grpc.block(ip, 0).await?;
        Ok(())
    }
}

#[derive(Subcommand)]
pub enum WhitelistCommands {
    #[command(about = "Add to XDP whitelist", long_about)]
    White {
        ip: String,
    },

    #[command(about = "Delete from XDP whitelist", long_about)]
    Del {
        ip: String,
    },
}
impl WhitelistCommands {
    pub async fn handle(self) -> ErrResult<()> {
        match self {
            Self::White { ip } => {
                Self::white(ip).await?;
            }
            Self::Del { ip } => {
                Self::delete(ip).await?;
            }
        }

        Ok(())
    }

    async fn white(ip: String) -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;
        grpc.white(ip).await?;
        Ok(())
    }

    async fn delete(ip: String) -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;
        grpc.block(ip, 0).await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Args)]
pub struct XdpRuleKeyWrapper {
    #[arg(long, help = "IP address")]
    pub ip: String,
    
    #[arg(long, help = "Port number")]
    pub port: u16,
    
    #[arg(long, help = "Ethernet type")]
    pub eth: String,
    
    #[arg(long, help = "IP protocol")]
    pub proto: String,
}

impl TryFrom<XdpRuleKeyWrapper> for XdpRuleKey {
    type Error = ErrRet;

    fn try_from(w: XdpRuleKeyWrapper) -> Result<Self, Self::Error> {
        Ok(XdpRuleKey {
            ip: EbpfIp::to_type(w.ip)?,
            port: EbpfPort(w.port),
            eth: EtherType::to_type(w.eth)?,
            proto: IpProto::to_type(w.proto)?,
        })
    }
}

#[derive(Debug, Clone, Args)]
pub struct XdpRuleValueWrapper {
    #[arg(long, help = "Action (Pass, Drop, Redirect etc.)")]
    pub action: String,

    #[command(flatten)]
    pub redirect: XdpRuleKeyWrapper,
}

impl TryFrom<XdpRuleValueWrapper> for XdpRuleValue {
    type Error = ErrRet;

    fn try_from(w: XdpRuleValueWrapper) -> Result<Self, Self::Error> {
        let redirect_key: XdpRuleKey = w.redirect.try_into()?;
            
        Ok(XdpRuleValue {
            action: XdpRuleAction::to_type(w.action)?,
            redirect: redirect_key,
        })
    }
}

#[derive(Subcommand)]
pub enum RulesCommands {
    #[command(about = "Rules list", long_about)]
    List,

    #[command(about = "XDP add rule", long_about)]
    Add {
        #[command(flatten)]
        key: XdpRuleKeyWrapper,

        #[command(flatten)]
        value: XdpRuleValueWrapper,
    },

    #[command(about = "XDP delete rule", long_about)]
    Del {
        #[command(flatten)]
        key: XdpRuleKeyWrapper,
    },
}
impl RulesCommands {
    pub async fn handle(self) -> ErrResult<()> {
        match self {
            Self::List => {
                Self::list().await?;
            }
            Self::Add { key, value } => {
                Self::add_rule(key, value).await?;
            }
            Self::Del { key } => {
                Self::del_rule(key).await?;
            }
        }

        Ok(())
    }

    async fn list() -> ErrResult<()> {


        Ok(())
    }

    async fn add_rule(key: XdpRuleKeyWrapper, value: XdpRuleValueWrapper) -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;

        let key = key.try_into()?;
        let value = value.try_into()?;

        grpc.add_rule(key, value).await?;
        Ok(())
    }

    async fn del_rule(key: XdpRuleKeyWrapper) -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;

        let key = key.try_into()?;

        grpc.del_rule(key).await?;
        Ok(())
    }
}