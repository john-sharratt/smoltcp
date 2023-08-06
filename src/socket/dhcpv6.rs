#[cfg(feature = "async")]
use core::task::Waker;

use crate::iface::Context;
use crate::time::{Duration, Instant};
use crate::wire::dhcpv6::{self, StatusCode};
use crate::wire::{
    Dhcpv6MessageType, Dhcpv6Packet, Dhcpv6Repr, IpProtocol, Ipv6Address, Ipv6Cidr, Ipv6Repr,
    UdpRepr, DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT, DHCP_MAX_DNS_SERVER_COUNT,
    Icmpv6Repr, NdiscRepr, NdiscRouterFlags, NdiscPrefixInformation, Dhcpv6ReprIaNa
};
use crate::wire::{Dhcpv6Option, HardwareAddress};
use heapless::Vec;

#[cfg(feature = "async")]
use super::WakerRegistration;

use super::PollAt;

const MAX_IDENTIFIER_LEN: usize = 128;

/// IPv6 configuration data provided by the DHCPV6 server.
#[derive(Debug, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Config<'a> {
    /// Information on how to reach the DHCP server that responded with DHCP
    /// configuration.
    pub server: ServerInfo,
    /// IP address
    pub address: Ipv6Cidr,
    /// Router address, also known as default gateway. Does not necessarily
    /// match the DHCP server's address.
    pub router: Option<Ipv6Address>,
    /// DNS servers
    pub dns_servers: Vec<Ipv6Address, DHCP_MAX_DNS_SERVER_COUNT>,
    /// Received DHCP packet
    pub packet: Option<Dhcpv6Packet<&'a [u8]>>,
}

/// Information on how to reach a DHCPV6 server.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ServerInfo {
    /// IP address to use as destination in outgoing packets
    pub address: Ipv6Address,
    /// Server identifier to use in outgoing packets. Usually equal to server_address,
    /// but may differ in some situations (eg DHCP relays)
    pub identifier: Vec<u8, MAX_IDENTIFIER_LEN>,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct RouterSolicitState {
    /// When to send next request
    retry_at: Instant,    
    /// How many retries have been done
    retry: u16,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct DhcpSolicitState {
    /// Client ID used for the transaction
    client_id: Vec<u8, MAX_IDENTIFIER_LEN>,
    /// When to send next request
    retry_at: Instant,
    /// How many retries have been done
    retry: u16,
    /// MTU of the network
    mtu: u32,
    /// Info about the prefix
    prefix_info: NdiscPrefixInformation,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct DhcpRequestState {
    /// Client ID used for the transaction
    client_id: Vec<u8, MAX_IDENTIFIER_LEN>,
    /// When to send next request
    retry_at: Instant,
    /// How many retries have been done
    retry: u16,
    /// The unique identifier for this IA_NA
    iaid: u32,
    /// Server we're trying to request from
    server: ServerInfo,
    /// IP address that we're trying to request.
    requested_ip: Ipv6Address,
    /// MTU of the network
    mtu: u32,
    /// Info about the prefix
    prefix_info: NdiscPrefixInformation,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct DhcpRenewState {
    /// Active network config
    config: Config<'static>,

    /// Client ID used for the transaction
    client_id: Vec<u8, MAX_IDENTIFIER_LEN>,
    /// The unique identifier for this IA_NA
    iaid: u32,
    /// Renew timer. When reached, we will start attempting
    /// to renew this lease with the DHCP server.
    /// Must be less or equal than `expires_at`.
    renew_at: Instant,
    /// Expiration timer. When reached, this lease is no longer valid, so it must be
    /// thrown away and the ethernet interface deconfigured.
    expires_at: Instant,
    /// MTU of the network
    #[allow(unused)]
    mtu: u32,
    /// Info about the prefix
    prefix_info: NdiscPrefixInformation,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum ClientState {
    /// Router solicitation
    RouterSolicit(RouterSolicitState),
    /// Discovering the DHCP server
    DhcpSolicit(DhcpSolicitState),
    /// Requesting an address
    DhcpRequesting(DhcpRequestState),
    /// Having an address, refresh it periodically.
    DhcpRenewing(DhcpRenewState),
}

/// Timeout and retry configuration.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RetryConfig {
    /// The REQUEST timeout doubles every 2 tries.
    pub initial_request_timeout: Duration,
    pub request_retries: u16,
    pub min_renew_timeout: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            initial_request_timeout: Duration::from_secs(2),
            request_retries: 5,
            min_renew_timeout: Duration::from_secs(60),
        }
    }
}

/// Return value for the `Dhcpv4Socket::poll` function
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Event<'a> {
    /// Configuration has been lost (for example, the lease has expired)
    Deconfigured,
    /// Configuration has been newly acquired, or modified.
    Configured(Config<'a>),
}

#[derive(Debug)]
pub struct Socket<'a> {
    /// State of the DHCP client.
    state: ClientState,

    /// Set to true on config/state change, cleared back to false by the `config` function.
    config_changed: bool,
    /// xid of the last sent message.
    transaction_id: u32,

    /// Max lease duration. If set, it sets a maximum cap to the server-provided lease duration.
    /// Useful to react faster to IP configuration changes and to test whether renews work correctly.
    max_lease_duration: Option<Duration>,

    retry_config: RetryConfig,

    /// Ignore NAKs.
    ignore_naks: bool,

    /// Server port config
    pub(crate) server_port: u16,

    /// Client port config
    pub(crate) client_port: u16,

    /// A buffer contains options additional to be added to outgoing DHCP
    /// packets.
    outgoing_options: &'a [Dhcpv6Option<'a>],
    /// A buffer containing all requested parameters.
    parameter_request_list: Option<&'a [u8]>,

    /// Incoming DHCP packets are copied into this buffer, overwriting the previous.
    receive_packet_buffer: Option<&'a mut [u8]>,

    /// Waker registration
    #[cfg(feature = "async")]
    waker: WakerRegistration,
}

pub(crate) enum DispatchEmit<'a> {
    Dhcp(Ipv6Repr, UdpRepr, Dhcpv6Repr<'a>),
    Icmp(Ipv6Repr, Icmpv6Repr<'a>)
}

/// DHCP client socket.
///
/// The socket acquires an IP address configuration through DHCP autonomously.
/// You must query the configuration with `.poll()` after every call to `Interface::poll()`,
/// and apply the configuration to the `Interface`.
impl<'a> Socket<'a> {
    /// Create a DHCPv4 socket
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Socket {
            state: ClientState::RouterSolicit(RouterSolicitState {
                retry_at: Instant::from_millis(0),
                retry: 0,
            }),
            config_changed: true,
            transaction_id: 1,
            max_lease_duration: None,
            retry_config: RetryConfig::default(),
            ignore_naks: false,
            outgoing_options: &[],
            parameter_request_list: None,
            receive_packet_buffer: None,
            #[cfg(feature = "async")]
            waker: WakerRegistration::new(),
            server_port: DHCPV6_SERVER_PORT,
            client_port: DHCPV6_CLIENT_PORT,
        }
    }

    /// Set the retry/timeouts configuration.
    pub fn set_retry_config(&mut self, config: RetryConfig) {
        self.retry_config = config;
    }

    /// Set the outgoing options.
    pub fn set_outgoing_options(&mut self, options: &'a [Dhcpv6Option<'a>]) {
        self.outgoing_options = options;
    }

    /// Set the buffer into which incoming DHCPV6 packets are copied into.
    pub fn set_receive_packet_buffer(&mut self, buffer: &'a mut [u8]) {
        self.receive_packet_buffer = Some(buffer);
    }

    /// Set the parameter request list.
    ///
    /// This should contain at least `OPT_SUBNET_MASK` (`1`), `OPT_ROUTER`
    /// (`3`), and `OPT_DOMAIN_NAME_SERVER` (`6`).
    pub fn set_parameter_request_list(&mut self, parameter_request_list: &'a [u8]) {
        self.parameter_request_list = Some(parameter_request_list);
    }

    /// Get the configured max lease duration.
    ///
    /// See also [`Self::set_max_lease_duration()`]
    pub fn max_lease_duration(&self) -> Option<Duration> {
        self.max_lease_duration
    }

    /// Set the max lease duration.
    ///
    /// When set, the lease duration will be capped at the configured duration if the
    /// DHCP server gives us a longer lease. This is generally not recommended, but
    /// can be useful for debugging or reacting faster to network configuration changes.
    ///
    /// If None, no max is applied (the lease duration from the DHCP server is used.)
    pub fn set_max_lease_duration(&mut self, max_lease_duration: Option<Duration>) {
        self.max_lease_duration = max_lease_duration;
    }

    /// Get whether to ignore NAKs.
    ///
    /// See also [`Self::set_ignore_naks()`]
    pub fn ignore_naks(&self) -> bool {
        self.ignore_naks
    }

    /// Set whether to ignore NAKs.
    ///
    /// This is not compliant with the DHCP RFCs, since theoretically
    /// we must stop using the assigned IP when receiving a NAK. This
    /// can increase reliability on broken networks with buggy routers
    /// or rogue DHCP servers, however.
    pub fn set_ignore_naks(&mut self, ignore_naks: bool) {
        self.ignore_naks = ignore_naks;
    }

    /// Set the server/client port
    ///
    /// Allows you to specify the ports used by DHCP.
    /// This is meant to support esoteric usecases allowed by the dhclient program.
    pub fn set_ports(&mut self, server_port: u16, client_port: u16) {
        self.server_port = server_port;
        self.client_port = client_port;
    }

    pub(crate) fn poll_at(&self, _cx: &Context) -> PollAt {
        let t = match &self.state {
            ClientState::RouterSolicit(state) => state.retry_at,
            ClientState::DhcpSolicit(state) => state.retry_at,
            ClientState::DhcpRequesting(state) => state.retry_at,
            ClientState::DhcpRenewing(state) => state.renew_at.min(state.expires_at),
        };
        PollAt::Time(t)
    }

    pub(crate) fn process_icmpv6(
        &mut self,
        cx: &mut Context,
        ip_repr: &Ipv6Repr,
        repr: &Icmpv6Repr,
        payload: &[u8],
    ) {
        let src_ip = ip_repr.src_addr;

        net_debug!(
            "ICMPv6 recv {:?} from {}",
            repr,
            src_ip            
        );

        // Copy over the payload into the receive packet buffer.
        if let Some(buffer) = self.receive_packet_buffer.as_mut() {
            if let Some(buffer) = buffer.get_mut(..payload.len()) {
                buffer.copy_from_slice(payload);
            }
        }

        match (&mut self.state, repr) {
            (ClientState::RouterSolicit(_), Icmpv6Repr::Ndisc(NdiscRepr::RouterAdvert {
                hop_limit: _hop_limit,
                flags,
                router_lifetime: _router_lifetime,
                reachable_time: _reachable_time,
                retrans_time: _retrans_time,
                lladdr: _lladdr,
                mtu,
                prefix_info
            })) => {
                // Flag that indicates if we are to go into stateful DHCP mode
                if flags.contains(NdiscRouterFlags::MANAGED) {
                    let mtu = match mtu {
                        Some(m) => *m,
                        None => {
                            net_debug!("ICMPv6 router advert ignored: missing MTU");
                            return;
                        }
                    };
                    if let Some(prefix_info) = prefix_info {
                        let mut client_id = Vec::new();
                        client_id.extend_from_slice(&cx.rand().rand_uuid()).ok();

                        self.state = ClientState::DhcpSolicit(
                            DhcpSolicitState {
                                client_id,
                                retry_at:Instant::from_millis(0),
                                retry: 0,
                                mtu: mtu,
                                prefix_info: prefix_info.clone(),
                            }
                        );
                    } else {
                        net_debug!(
                            "ICMPv6 router advert ignored: missing prefix info"
                        );
                    }
                    
                } else {
                    // Using auto-configuration instead which means there is no DHCPv6
                    // server and we can just set the addresses directly


                    net_debug!(
                        "ICMPv6 router advert ignored: router is not managed"
                    );
                }
            }
            (ClientState::RouterSolicit(_), _) => {
                net_debug!(
                    "ICMPv6 ignoring {:?}: unexpected in current state",
                    repr
                );
            }
            _ => {
                // silently ignore ICMP packets when we are pasted the route solicit phase
            }
        }
    }

    pub(crate) fn process_udp(
        &mut self,
        cx: &mut Context,
        ip_repr: &Ipv6Repr,
        repr: &UdpRepr,
        payload: &[u8],
    ) {
        let src_ip = ip_repr.src_addr;

        // This is enforced in interface.rs.
        assert!(repr.src_port == self.server_port && repr.dst_port == self.client_port);

        let dhcp_packet = match Dhcpv6Packet::new_checked(payload) {
            Ok(dhcp_packet) => dhcp_packet,
            Err(e) => {
                net_debug!("DHCPv6 invalid pkt from {}: {:?}", src_ip, e);
                return;
            }
        };
        let dhcp_repr = match Dhcpv6Repr::parse(&dhcp_packet) {
            Ok(dhcp_repr) => dhcp_repr,
            Err(e) => {
                net_debug!("DHCPv6 error parsing pkt from {}: {:?}", src_ip, e);
                return;
            }
        };

        let Some(HardwareAddress::Ethernet(_ethernet_addr)) = cx.hardware_addr() else {
            panic!("using DHCPv6 socket with a non-ethernet hardware address.");
        };

        if dhcp_repr.transaction_id != self.transaction_id {
            return;
        }
        let _server_identifier = match dhcp_repr.server_id {
            Some(server_identifier) => server_identifier,
            None => {
                net_debug!(
                    "DHCPv6 ignoring {:?} because missing server_identifier",
                    dhcp_repr.message_type
                );
                return;
            }
        };

        net_debug!(
            "DHCPv6 recv {:?} from {}: {:?}",
            dhcp_repr.message_type,
            src_ip,
            dhcp_repr
        );

        // Copy over the payload into the receive packet buffer.
        if let Some(buffer) = self.receive_packet_buffer.as_mut() {
            if let Some(buffer) = buffer.get_mut(..payload.len()) {
                buffer.copy_from_slice(payload);
            }
        }

        match (&mut self.state, dhcp_repr.message_type) {
            (ClientState::RouterSolicit(_), _) => {
                // Silently ignore DHCP requests when we are still soliciting the router address
            }
            (ClientState::DhcpSolicit(state), Dhcpv6MessageType::Advertise) => {
                let ia_na = match dhcp_repr.ia_na {
                    Some(i) => i,
                    None => {
                        net_debug!("DHCPv6 ignoring advertise because its missing an IA_NA section");
                        return;
                    }
                };
                if ia_na.addresses.is_empty() {
                    net_debug!("DHCPv6 ignoring advertise because its missing addresses in the IA_NA section");
                    return;
                }
                match dhcp_repr.client_id {
                    Some(s) if s.len() == state.client_id.len() && s == state.client_id => {},
                    Some(_) => {
                        net_debug!("DHCPv6 ignoring advertise because its missing client identifier does not match");
                        return;
                    }
                    None => {
                        net_debug!("DHCPv6 ignoring advertise because its missing a client identifier");
                        return;
                    }
                };
                let server_id = match dhcp_repr.server_id {
                    Some(s) => {
                        let mut id = Vec::new();
                        id.extend_from_slice(s).ok();
                        id
                    },
                    None => {
                        net_debug!("DHCPv6 ignoring advertise because its missing a server identifier");
                        return;
                    }
                };

                let mut client_id = Vec::new();
                client_id.extend_from_slice(&state.client_id).ok();

                self.state = ClientState::DhcpRequesting(DhcpRequestState {
                    client_id,
                    retry_at: cx.now(),
                    retry: 0,
                    server: ServerInfo {
                        address: src_ip,
                        identifier: server_id,
                    },
                    requested_ip: ia_na.addresses.first().unwrap().addr,
                    mtu: state.mtu,
                    iaid: ia_na.iaid,
                    prefix_info: state.prefix_info.clone(),
                });     
            }
            (ClientState::DhcpRequesting(state), Dhcpv6MessageType::Confirm) => {
                let ia_na = match &dhcp_repr.ia_na {
                    Some(i) => i,
                    None => {
                        net_debug!("DHCPv6 ignoring confirm because its missing an IA_NA section");
                        return;
                    }
                };
                match dhcp_repr.client_id {
                    Some(s) if s.len() == state.client_id.len() && s == state.client_id => {},
                    Some(_) => {
                        net_debug!("DHCPv6 ignoring confirm because its missing client identifier does not match");
                        return;
                    }
                    None => {
                        net_debug!("DHCPv6 ignoring confirm because its missing a client identifier");
                        return;
                    }
                };
                match dhcp_repr.server_id {
                    Some(s) if s.len() == state.server.identifier.len() && s == state.server.identifier => {},
                    Some(_) => {
                        net_debug!("DHCPv6 ignoring confirm because its missing server identifier does not match");
                        return;
                    }
                    None => {
                        net_debug!("DHCPv6 ignoring confirm because its missing a server identifier");
                        return;
                    }
                };
                if let Some((config, renew_at, expires_at)) =
                    Self::parse_ack(
                        cx.now(),
                        src_ip,
                        &dhcp_repr,
                        self.max_lease_duration,
                        state.server.clone(),
                        &ia_na,
                        &state.prefix_info
                    )
                {
                    let mut client_id = Vec::new();
                    client_id.extend_from_slice(&state.client_id).ok();

                    self.state = ClientState::DhcpRenewing(DhcpRenewState {
                        client_id,
                        iaid: state.iaid,
                        config,
                        renew_at,
                        expires_at,
                        mtu: state.mtu,
                        prefix_info: state.prefix_info,
                    });
                    self.config_changed();
                }
            }
            (ClientState::DhcpRequesting(_), Dhcpv6MessageType::Decline) => {
                if !self.ignore_naks {
                    self.reset();
                }
            }
            (ClientState::DhcpRenewing(state), Dhcpv6MessageType::Confirm) => {
                let ia_na = match &dhcp_repr.ia_na {
                    Some(i) => i,
                    None => {
                        net_debug!("DHCPv6 ignoring advertise because its missing an IA_NA section");
                        return;
                    }
                };
                match dhcp_repr.client_id {
                    Some(s) if s.len() == state.client_id.len() && s == state.client_id => {},
                    Some(_) => {
                        net_debug!("DHCPv6 ignoring confirm because its missing client identifier does not match");
                        return;
                    }
                    None => {
                        net_debug!("DHCPv6 ignoring confirm because its missing a client identifier");
                        return;
                    }
                };
                match dhcp_repr.server_id {
                    Some(s) if s.len() == state.config.server.identifier.len() && s == state.config.server.identifier => {},
                    Some(_) => {
                        net_debug!("DHCPv6 ignoring confirm because its missing server identifier does not match");
                        return;
                    }
                    None => {
                        net_debug!("DHCPv6 ignoring confirm because its missing a server identifier");
                        return;
                    }
                };
                if let Some((config, renew_at, expires_at)) = Self::parse_ack(
                    cx.now(),
                    src_ip,
                    &dhcp_repr,
                    self.max_lease_duration,
                    state.config.server.clone(),
                    &ia_na,
                    &state.prefix_info
                ) {
                    state.renew_at = renew_at;
                    state.expires_at = expires_at;
                    // The `receive_packet_buffer` field isn't populated until
                    // the client asks for the state, but receiving any packet
                    // will change it, so we indicate that the config has
                    // changed every time if the receive packet buffer is set,
                    // but we only write changes to the rest of the config now.
                    let config_changed =
                        state.config != config || self.receive_packet_buffer.is_some();
                    if state.config != config {
                        state.config = config;
                    }
                    if config_changed {
                        self.config_changed();
                    }
                }
            }
            (ClientState::DhcpRenewing(_), Dhcpv6MessageType::Decline) => {
                if !self.ignore_naks {
                    self.reset();
                }
            }
            _ => {
                net_debug!(
                    "DHCPv6 ignoring {:?}: unexpected in current state",
                    dhcp_repr.message_type
                );
            }
        }
    }

    fn parse_ack(
        now: Instant,
        src_ip: Ipv6Address,
        dhcp_repr: &Dhcpv6Repr,
        max_lease_duration: Option<Duration>,
        server: ServerInfo,
        ia_na: &Dhcpv6ReprIaNa,
        prefix_info: &NdiscPrefixInformation,
    ) -> Option<(Config<'static>, Instant, Instant)> {
        let prefix_len = prefix_info.prefix_len;

        if ia_na.addresses.is_empty() {
            net_debug!("DHCPv6 ignoring confirm because its missing addresses in the IA_NA section");
            return None;
        }

        if StatusCode::Success != ia_na.status_code.as_ref().map(|s| s.status_code).unwrap_or(StatusCode::Success) {
            net_debug!("DHCPv6 ignoring confirm its status code is not success");
            return None;
        }

        let your_addr = ia_na.addresses.first().unwrap().addr;

        let mut lease_duration = Duration::from_secs(ia_na.t1 as u64);
        if let Some(max_lease_duration) = max_lease_duration {
            lease_duration = lease_duration.min(max_lease_duration);
        }

        let mut dns_servers = Vec::new();

        dhcp_repr
            .dns_servers
            .iter()
            .flat_map(|s| s.addresses.iter())
            .filter(|s| s.is_unicast())
            .for_each(|a| {
                dns_servers.push(*a).ok();
            });

        let config = Config {
            server,
            address: Ipv6Cidr::new(your_addr, prefix_len),
            router: Some(src_ip),
            dns_servers,
            packet: None,
        };

        let renew_duration = Duration::from_secs(ia_na.t2 as u64);
        let renew_at = now + renew_duration;
        let expires_at = now + lease_duration;

        Some((config, renew_at, expires_at))
    }

    #[cfg(not(test))]
    fn random_transaction_id(cx: &mut Context) -> u32 {
        cx.rand().rand_u32()
    }

    #[cfg(test)]
    fn random_transaction_id(_cx: &mut Context) -> u32 {
        0x12345678
    }

    pub(crate) fn dispatch<F, E>(&mut self, cx: &mut Context, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut Context, DispatchEmit) -> Result<(), E>,
    {
        // note: Dhcpv4Socket is only usable in ethernet mediums, so the
        // unwrap can never fail.
        let Some(HardwareAddress::Ethernet(ethernet_addr)) = cx.hardware_addr() else {
            panic!("using DHCPv6 socket with a non-ethernet hardware address.");
        };

        // We don't directly modify self.transaction_id because sending the packet
        // may fail. We only want to update state after succesfully sending.
        let next_transaction_id = Self::random_transaction_id(cx);

        let mut dhcp_repr = Dhcpv6Repr {
            message_type: Dhcpv6MessageType::Solicit,
            transaction_id: next_transaction_id,
            client_id: Some(ethernet_addr.as_bytes()),
            server_id: None,
            elapsed_time: None,
            ia_na: None,
            ia_ta: None,
            request_options: None,
            dns_servers: None,
            additional_options: &[],
        };
        dhcp_repr.add_request_option(dhcpv6::field::OPT_DNS_SERVERS);

        let udp_repr = UdpRepr {
            src_port: self.client_port,
            dst_port: self.server_port,
        };

        let mut ipv6_repr = Ipv6Repr {
            src_addr: Ipv6Address::UNSPECIFIED,
            dst_addr: Ipv6Address::LINK_LOCAL_ALL_ROUTERS,
            next_header: IpProtocol::Udp,
            payload_len: 0, // filled right before emit
            hop_limit: 64,
        };

        match &mut self.state {
            ClientState::RouterSolicit(state) => {
                if cx.now() < state.retry_at {
                    return Ok(());
                }

                // Instead of sending a DHCPv6 packet we need to send a router solicit message
                let icmp_repr = Icmpv6Repr::Ndisc(NdiscRepr::RouterSolicit {
                    lladdr: Some(ethernet_addr.into())
                });
                ipv6_repr = Ipv6Repr {
                    src_addr: Ipv6Address::UNSPECIFIED,
                    dst_addr: Ipv6Address::LINK_LOCAL_ALL_ROUTERS,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: icmp_repr.buffer_len(),
                    hop_limit: 64,
                };
                // send packet
                net_debug!(
                    "ICMPv6 send ROUTER SOLICIT to {}: {:?}",
                    ipv6_repr.dst_addr,
                    icmp_repr
                );
                emit(cx, DispatchEmit::Icmp(ipv6_repr, icmp_repr))?;

                // Exponential backoff: Double every 2 retries, up to a maximum of 8 times.
                state.retry_at = cx.now()
                    + (self.retry_config.initial_request_timeout << (state.retry.min(16) as u32 / 2));
                state.retry += 1;
                self.transaction_id = next_transaction_id;
                Ok(())
            }
            ClientState::DhcpSolicit(state) => {
                if cx.now() < state.retry_at {
                    return Ok(());
                }

                // send packet
                net_debug!(
                    "DHCPv6 send solicit to {}: {:?}",
                    ipv6_repr.dst_addr,
                    dhcp_repr
                );
                ipv6_repr.payload_len = udp_repr.header_len() + dhcp_repr.buffer_len();
                emit(cx, DispatchEmit::Dhcp(ipv6_repr, udp_repr, dhcp_repr))?;

                // Exponential backoff: Double every 2 retries, up to a maximum of 8 times.
                state.retry_at = cx.now()
                    + (self.retry_config.initial_request_timeout << (state.retry.min(16) as u32 / 2));
                    state.retry += 1;
                self.transaction_id = next_transaction_id;
                Ok(())
            }
            ClientState::DhcpRequesting(state) => {
                if cx.now() < state.retry_at {
                    return Ok(());
                }

                if state.retry >= self.retry_config.request_retries {
                    net_debug!("DHCPv6 request retries exceeded, restarting discovery");
                    drop(state);
                    drop(dhcp_repr);

                    self.reset();
                    return Ok(());
                }

                let mut addresses = Vec::new();
                addresses.push(dhcpv6::ReprIaAddr {
                    addr: state.requested_ip,
                    preferred_lifetime: 604800,
                    valid_lifetime: 2592000,
                    additional_options: &[]
                }).ok();

                dhcp_repr.message_type = Dhcpv6MessageType::Request;
                dhcp_repr.server_id = Some(&state.server.identifier);
                dhcp_repr.ia_na = Some(Dhcpv6ReprIaNa {
                    iaid: state.iaid,
                    t1: 0,
                    t2: 0,
                    addresses,
                    status_code: None,
                    additional_options: &[],
                });

                net_debug!(
                    "DHCPv6 send REQUEST to {}: {:?}",
                    ipv6_repr.dst_addr,
                    dhcp_repr
                );
                ipv6_repr.payload_len = udp_repr.header_len() + dhcp_repr.buffer_len();
                emit(cx, DispatchEmit::Dhcp(ipv6_repr, udp_repr, dhcp_repr))?;

                // Exponential backoff: Double every 2 retries, up to a maximum of 8 times.
                state.retry_at = cx.now()
                    + (self.retry_config.initial_request_timeout << (state.retry.min(16) as u32 / 2));
                state.retry += 1;

                self.transaction_id = next_transaction_id;
                Ok(())
            }
            ClientState::DhcpRenewing(state) => {
                if state.expires_at <= cx.now() {
                    net_debug!("DHCPv6 lease expired");
                    drop(state);
                    drop(dhcp_repr);

                    self.reset();
                    // return Ok so we get polled again
                    return Ok(());
                }

                if cx.now() < state.renew_at {
                    return Ok(());
                }

                let mut addresses = Vec::new();
                addresses.push(dhcpv6::ReprIaAddr {
                    addr: state.config.address.address(),
                    preferred_lifetime: 604800,
                    valid_lifetime: 2592000,
                    additional_options: &[]
                }).ok();

                ipv6_repr.src_addr = state.config.address.address();
                ipv6_repr.dst_addr = state.config.server.address;
                dhcp_repr.message_type = Dhcpv6MessageType::Request;
                
                dhcp_repr.server_id = Some(&state.config.server.identifier);
                dhcp_repr.ia_na = Some(Dhcpv6ReprIaNa {
                    iaid: state.iaid,
                    t1: 0,
                    t2: 0,
                    addresses,
                    status_code: None,
                    additional_options: &[],
                });

                net_debug!("DHCPv6 send RENEW to {}: {:?}", ipv6_repr.dst_addr, dhcp_repr);
                ipv6_repr.payload_len = udp_repr.header_len() + dhcp_repr.buffer_len();
                emit(cx, DispatchEmit::Dhcp(ipv6_repr, udp_repr, dhcp_repr))?;

                // In both RENEWING and REBINDING states, if the client receives no
                // response to its DHCPREQUEST message, the client SHOULD wait one-half
                // of the remaining time until T2 (in RENEWING state) and one-half of
                // the remaining lease time (in REBINDING state), down to a minimum of
                // 60 seconds, before retransmitting the DHCPREQUEST message.
                state.renew_at = cx.now()
                    + self
                        .retry_config
                        .min_renew_timeout
                        .max((state.expires_at - cx.now()) / 2);
                self.transaction_id = next_transaction_id;
                Ok(())
            }
        }
    }

    /// Reset state and restart discovery phase.
    ///
    /// Use this to speed up acquisition of an address in a new
    /// network if a link was down and it is now back up.
    pub fn reset(&mut self) {
        net_trace!("DHCPv6 reset");
        if let ClientState::DhcpRenewing(_) = &self.state {
            self.config_changed();
        }
        self.state = ClientState::RouterSolicit(RouterSolicitState {
            retry_at: Instant::from_millis(0),
            retry: 0,
        });
    }

    /// Query the socket for configuration changes.
    ///
    /// The socket has an internal "configuration changed" flag. If
    /// set, this function returns the configuration and resets the flag.
    pub fn poll(&mut self) -> Option<Event> {
        if !self.config_changed {
            None
        } else if let ClientState::DhcpRenewing(state) = &self.state {
            self.config_changed = false;
            Some(Event::Configured(Config {
                server: state.config.server.clone(),
                address: state.config.address,
                router: state.config.router,
                dns_servers: state.config.dns_servers.clone(),
                packet: self
                    .receive_packet_buffer
                    .as_deref()
                    .map(Dhcpv6Packet::new_unchecked),
            }))
        } else {
            self.config_changed = false;
            Some(Event::Deconfigured)
        }
    }

    /// This function _must_ be called when the configuration provided to the
    /// interface, by this DHCP socket, changes. It will update the `config_changed` field
    /// so that a subsequent call to `poll` will yield an event, and wake a possible waker.
    pub(crate) fn config_changed(&mut self) {
        self.config_changed = true;
        #[cfg(feature = "async")]
        self.waker.wake_all();
    }

    /// Register a waker.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `poll` method calls, which indicates a new state in the DHCP configuration
    /// provided by this DHCP socket.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    #[cfg(feature = "async")]
    pub fn register_waker(&mut self, waker: &Waker) {
        self.waker.register(waker)
    }

    /// Adds another waker.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `poll` method calls, which indicates a new state in the DHCP configuration
    /// provided by this DHCP socket.
    ///
    /// Notes:
    ///
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    #[cfg(feature = "async")]
    pub fn add_waker(&mut self, waker: &Waker) {
        self.waker.add(waker)
    }

    /// Clears all the wakers that were assigned to this socket
    #[cfg(feature = "async")]
    pub fn clear_waker(&mut self) {
        self.waker.clear();
    }
}
