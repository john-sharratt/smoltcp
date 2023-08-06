// See https://datatracker.ietf.org/doc/html/rfc8415 for the DHCPv6 specification.

use alloc::borrow::Cow;
use byteorder::{ByteOrder, NetworkEndian};
use core::{iter, fmt};
use heapless::Vec;

use super::{Error, Result};

pub const SERVER_PORT: u16 = 547;
pub const CLIENT_PORT: u16 = 546;
pub const MAX_REQUEST_OPTIONS: usize = 16;
pub const MAX_IA_ADDRESSES: usize = 16;
pub const MAX_DNS_ADDRESSES: usize = 16;

enum_with_unknown! {
    /// The possible message types of a DHCP packet.
    pub enum MessageType(u8) {
        Solicit = 1,
        Advertise = 2,
        Request = 3,
        Confirm = 4,
        Renew = 5,
        Rebind = 6,
        Reply = 7,
        Release = 8,
        Decline = 9,
        Reconfigure = 10,
        InformationRequest = 11,
        RelayForw = 12,
        RelayRepl = 13,
        LeaseQuery = 14,
        LeaseQueryReply = 15,
        LeaseQueryDone = 16,
        LeaseQueryData = 17,
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Solicit => write!(f, "solicit"),
            Self::Advertise => write!(f, "advertise"),
            Self::Request => write!(f, "request"),
            Self::Confirm => write!(f, "confirm"),
            Self::Renew => write!(f, "renew"),
            Self::Rebind => write!(f, "rebind"),
            Self::Reply => write!(f, "reply"),
            Self::Release => write!(f, "release"),
            Self::Decline => write!(f, "decline"),
            Self::Reconfigure => write!(f, "reconfigure"),
            Self::InformationRequest => write!(f, "information-request"),
            Self::RelayForw => write!(f, "relay-forw"),
            Self::RelayRepl => write!(f, "relay-repl"),
            Self::LeaseQuery => write!(f, "lease-query"),
            Self::LeaseQueryReply => write!(f, "lease-query-reply"),
            Self::LeaseQueryDone => write!(f, "lease-query-done"),
            Self::LeaseQueryData => write!(f, "lease-query-data"),
            Self::Unknown(a) => write!(f, "unknown({a})"),
        }
    }
}

/// A buffer for DHCP options.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Dhcpv6OptionWriter<'a> {
    /// The underlying buffer, directly from the DHCP packet representation.
    buffer: &'a mut [u8],
}

impl<'a> Dhcpv6OptionWriter<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer }
    }

    /// Emit a  [`Dhcpv6Option`] into a [`Dhcpv6OptionWriter`].
    pub fn emit(&mut self, option: Dhcpv6Option<'_>) -> Result<()> {
        if option.data.len() > u16::MAX as _ {
            return Err(Error);
        }

        let total_len = 4 + option.data.len();
        if self.buffer.len() < total_len {
            return Err(Error);
        }

        let (buf, rest) = core::mem::take(&mut self.buffer).split_at_mut(total_len);
        self.buffer = rest;

        NetworkEndian::write_u16(&mut buf[0..2], option.kind);
        NetworkEndian::write_u16(&mut buf[2..4], option.data.len() as u16);
        buf[4..].copy_from_slice(option.data);        

        Ok(())
    }
}

// The format of DHCP options is:

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          option-code          |           option-len          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          option-data                          |
// |                      (option-len octets)                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//                   Figure 12: Option Format
//
// option-code          An unsigned integer identifying the specific
//                     option type carried in this option.
//                     A 2-octet field.
//
// option-len           An unsigned integer giving the length of the
//                     option-data field in this option in octets.
//                     A 2-octet field.
//
// option-data          The data for the option; the format of this
//                     data depends on the definition of the option.
//                     A variable-length field (the length, in
//                     octets, is specified by option-len).
//
// DHCP options are scoped by using encapsulation.  Some options apply
// generally to the client, some are specific to an IA, and some are
// specific to the addresses within an IA.  These latter two cases are
// discussed in Sections 21.4, 21.5, and 21.6.
//
/// A representation of a single DHCP option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Dhcpv6Option<'a> {
    pub kind: u16,
    pub data: &'a [u8],
}

/// A read/write wrapper around a Dynamic Host Configuration Protocol packet buffer.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

pub(crate) mod field {
    #![allow(non_snake_case)]
    #![allow(unused)]

    use crate::wire::field::*;

    pub const MTYPE: usize = 0;
    pub const XID: Field = 1..4;
    pub const OPTIONS: Rest = 4..;
    
    // The Client Identifier option is used to carry a DUID (see Section 11)
    // that identifies the client.  The format of the Client Identifier
    // option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |        OPTION_CLIENTID        |          option-len           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    .                                                               .
    //    .                              DUID                             .
    //    .                        (variable length)                      .
    //    .                                                               .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //              Figure 13: Client Identifier Option Format
    //
    //    option-code          OPTION_CLIENTID (1).
    //    option-len           Length of DUID in octets.
    //    DUID                 The DUID for the client.
    pub const OPT_CLIENTID: u16 = 1;

    // The Server Identifier option is used to carry a DUID (see Section 11)
    // that identifies the server.  The format of the Server Identifier
    // option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |        OPTION_SERVERID        |          option-len           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    .                                                               .
    //    .                              DUID                             .
    //    .                        (variable length)                      .
    //    .                                                               .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //              Figure 14: Server Identifier Option Format
    //
    //              option-code          OPTION_SERVERID (2).
    //              option-len           Length of DUID in octets.
    //              DUID                 The DUID for the server.
    pub const OPT_SERVERID: u16 = 2;

    // The Identity Association for Non-temporary Addresses (IA_NA) option
    // is used to carry an IA_NA, the parameters associated with the IA_NA,
    // and the non-temporary addresses associated with the IA_NA.
    //
    // Addresses appearing in an IA_NA option are not temporary addresses
    // (see Section 21.5).
    //
    // The format of the IA_NA option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |          OPTION_IA_NA         |          option-len           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                        IAID (4 octets)                        |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                              T1                               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                              T2                               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                                                               |
    //    .                         IA_NA-options                         .
    //    .                                                               .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //      Figure 15: Identity Association for Non-temporary Addresses
    //                             Option Format
    //
    //    option-code          OPTION_IA_NA (3).
    //
    //    option-len           12 + length of IA_NA-options field.
    //
    //    IAID                 The unique identifier for this IA_NA; the
    //                         IAID must be unique among the identifiers for
    //                         all of this client's IA_NAs.  The number
    //                         space for IA_NA IAIDs is separate from the
    //                         number space for other IA option types (i.e.,
    //                         IA_TA and IA_PD).  A 4-octet field containing
    //                         an unsigned integer.
    //                         T1                   The time interval after which the client
    //                         should contact the server from which the
    //                         addresses in the IA_NA were obtained to
    //                         extend the lifetimes of the addresses
    //                         assigned to the IA_NA; T1 is a time duration
    //                         relative to the current time expressed in
    //                         units of seconds.  A 4-octet field containing
    //                         an unsigned integer.
    //
    //    T2                   The time interval after which the client
    //                         should contact any available server to extend
    //                         the lifetimes of the addresses assigned to
    //                         the IA_NA; T2 is a time duration relative to
    //                         the current time expressed in units of
    //                         seconds.  A 4-octet field containing an
    //                         unsigned integer.
    //
    //    IA_NA-options        Options associated with this IA_NA.  A
    //                         variable-length field (12 octets less than
    //                         the value in the option-len field).
    //
    // The IA_NA-options field encapsulates those options that are specific
    // to this IA_NA.  For example, all of the IA Address options (see
    // Section 21.6) carrying the addresses associated with this IA_NA are
    // in the IA_NA-options field.
    //
    // Each IA_NA carries one "set" of non-temporary addresses; it is up to
    // the server policy to determine how many addresses are assigned, but
    // typically at most one address is assigned from each prefix assigned
    // to the link to which the client is attached.
    //
    // An IA_NA option may only appear in the options area of a DHCP
    // message.  A DHCP message may contain multiple IA_NA options (though
    // each must have a unique IAID).
    //
    // The status of any operations involving this IA_NA is indicated in a
    // Status Code option (see Section 21.13) in the IA_NA-options field.
    //
    // Note that an IA_NA has no explicit "lifetime" or "lease length" of
    // its own.  When the valid lifetimes of all of the addresses in an
    // IA_NA have expired, the IA_NA can be considered as having expired.
    // T1 and T2 are included to give servers explicit control over when a
    // client recontacts the server about a specific IA_NA.
    //
    // In a message sent by a client to a server, the T1 and T2 fields
    // SHOULD be set to 0.  The server MUST ignore any values in these
    // fields in messages received from a client.
    // In a message sent by a server to a client, the client MUST use the
    // values in the T1 and T2 fields for the T1 and T2 times, unless values
    // in those fields are 0.  The values in the T1 and T2 fields are the
    // number of seconds until T1 and T2 and are calculated since reception
    // of the message.
    //
    // As per Section 7.7, the value 0xffffffff is taken to mean "infinity"
    // and should be used carefully.
    //
    // The server selects the T1 and T2 values to allow the client to extend
    // the lifetimes of any addresses in the IA_NA before the lifetimes
    // expire, even if the server is unavailable for some short period of
    // time.  Recommended values for T1 and T2 are 0.5 and 0.8 times the
    // shortest preferred lifetime of the addresses in the IA that the
    // server is willing to extend, respectively.  If the "shortest"
    // preferred lifetime is 0xffffffff ("infinity"), the recommended T1 and
    // T2 values are also 0xffffffff.  If the time at which the addresses in
    // an IA_NA are to be renewed is to be left to the discretion of the
    // client, the server sets the T1 and T2 values to 0.  The client MUST
    // follow the rules defined in Section 14.2.
    //
    // If a client receives an IA_NA with T1 greater than T2 and both T1 and
    // T2 are greater than 0, the client discards the IA_NA option and
    // processes the remainder of the message as though the server had not
    // included the invalid IA_NA option.
    pub const OPT_IA_NA: u16 = 3;

    // The Identity Association for Temporary Addresses (IA_TA) option is
    // used to carry an IA_TA, the parameters associated with the IA_TA, and
    // the addresses associated with the IA_TA.  All of the addresses in
    // this option are used by the client as temporary addresses, as defined
    // in [RFC4941].  The format of the IA_TA option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |          OPTION_IA_TA         |          option-len           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                        IAID (4 octets)                        |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                                                               |
    //    .                         IA_TA-options                         .
    //    .                                                               .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // Figure 16: Identity Association for Temporary Addresses Option Format
    //     option-code          OPTION_IA_TA (4).
    //
    //     option-len           4 + length of IA_TA-options field.
    //
    //     IAID                 The unique identifier for this IA_TA; the
    //                         IAID must be unique among the identifiers for
    //                         all of this client's IA_TAs.  The number
    //                         space for IA_TA IAIDs is separate from the
    //                         number space for other IA option types (i.e.,
    //                         IA_NA and IA_PD).  A 4-octet field containing
    //                         an unsigned integer.
    //
    //     IA_TA-options        Options associated with this IA_TA.  A
    //                         variable-length field (4 octets less than the
    //                         value in the option-len field).
    //
    // The IA_TA-options field encapsulates those options that are specific
    // to this IA_TA.  For example, all of the IA Address options (see
    // Section 21.6) carrying the addresses associated with this IA_TA are
    // in the IA_TA-options field.
    //
    // Each IA_TA carries one "set" of temporary addresses.  It is up to the
    // server policy to determine how many addresses are assigned.
    //
    // An IA_TA option may only appear in the options area of a DHCP
    // message.  A DHCP message may contain multiple IA_TA options (though
    // each must have a unique IAID).
    //
    // The status of any operations involving this IA_TA is indicated in a
    // Status Code option (see Section 21.13) in the IA_TA-options field.
    //
    // Note that an IA has no explicit "lifetime" or "lease length" of its
    // own.  When the valid lifetimes of all of the addresses in an IA_TA
    // have expired, the IA can be considered as having expired.
    //
    // An IA_TA option does not include values for T1 and T2.  A client MAY
    // request that the valid lifetime on temporary addresses be extended by
    // including the addresses in an IA_TA option sent in a Renew or Rebind
    // message to a server.  For example, a client would request an
    // extension on the valid lifetime of a temporary address to allow an
    // application to continue to use an established TCP connection.
    // Extending only the valid, but not the preferred, lifetime means the
    // address will end up in a deprecated state eventually.  Existing
    // connections could continue, but no new ones would be created using
    // that address.
    //
    // The client obtains new temporary addresses by sending an IA_TA option
    // with a new IAID to a server.  Requesting new temporary addresses from
    // the server is the equivalent of generating new temporary addresses as
    // described in [RFC4941].  The server will generate new temporary
    // addresses and return them to the client.  The client should request
    // new temporary addresses before the lifetimes on the previously
    // assigned addresses expire.

    // A server MUST return the same set of temporary addresses for the same
    // IA_TA (as identified by the IAID) as long as those addresses are
    // still valid.  After the lifetimes of the addresses in an IA_TA have
    // expired, the IAID may be reused to identify a new IA_TA with new
    // temporary addresses.
    pub const OPT_IA_TA: u16 = 4;

    // The IA Address option is used to specify an address associated with
    // an IA_NA or an IA_TA.  The IA Address option must be encapsulated in
    // the IA_NA-options field of an IA_NA option (see Section 21.4) or the
    // IA_TA-options field of an IA_TA option (see Section 21.5).  The
    // IAaddr-options field encapsulates those options that are specific to
    // this address.
    //
    // The format of the IA Address option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |          OPTION_IAADDR        |          option-len           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                                                               |
    //    |                         IPv6-address                          |
    //    |                                                               |
    //    |                                                               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                      preferred-lifetime                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                        valid-lifetime                         |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    .                                                               .
    //    .                        IAaddr-options                         .
    //    .                                                               .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                  Figure 17: IA Address Option Format
    //
    //                  option-code          OPTION_IAADDR (5).
    //
    //                  option-len           24 + length of IAaddr-options field.
    //         
    //                  IPv6-address         An IPv6 address.  A client MUST NOT form an
    //                                       implicit prefix with a length other than 128
    //                                       for this address.  A 16-octet field.
    //         
    //                  preferred-lifetime   The preferred lifetime for the address in the
    //                                       option, expressed in units of seconds.  A
    //                                       4-octet field containing an unsigned integer.
    //         
    //                  valid-lifetime       The valid lifetime for the address in the
    //                                       option, expressed in units of seconds.  A
    //                                       4-octet field containing an unsigned integer.
    //         
    //                  IAaddr-options       Options associated with this address.  A
    //                                       variable-length field (24 octets less than
    //                                       the value in the option-len field).
    //         
    //               In a message sent by a client to a server, the preferred-lifetime and
    //               valid-lifetime fields SHOULD be set to 0.  The server MUST ignore any
    //               received values.
    //         
    //               The client SHOULD NOT send the IA Address option with an unspecified
    //               address (::).
    //         
    //               In a message sent by a server to a client, the client MUST use the
    //               values in the preferred-lifetime and valid-lifetime fields for the
    //               preferred and valid lifetimes.  The values in these fields are the
    //               number of seconds remaining in each lifetime.
    //         
    //               The client MUST discard any addresses for which the preferred
    //               lifetime is greater than the valid lifetime.
    //         
    //               As per Section 7.7, if the valid lifetime of an address is
    //               0xffffffff, it is taken to mean "infinity" and should be used
    //               carefully.
    //         
    //               More than one IA Address option can appear in an IA_NA option or an
    //               IA_TA option.
    //
    //               The status of any operations involving this IA Address is indicated
    //               in a Status Code option in the IAaddr-options field, as specified in
    //               Section 21.13.
    pub const OPT_IA_ADDR: u16 = 5;

    // The Option Request option is used to identify a list of options in a
    // message between a client and a server.  The format of the Option
    // Request option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     |           OPTION_ORO          |           option-len          |
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     |    requested-option-code-1    |    requested-option-code-2    |
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     |                              ...                              |
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                 Figure 18: Option Request Option Format
    //
    //     option-code               OPTION_ORO (6).
    //
    //     option-len                2 * number of requested options.
    //
    //     requested-option-code-n   The option code for an option requested
    //                                 by the client.  Each option code is a
    //                                 2-octet field containing an unsigned
    //                                 integer.
    //
    // A client MUST include an Option Request option in a Solicit, Request,
    // Renew, Rebind, or Information-request message to inform the server
    // about options the client wants the server to send to the client.  For
    // certain message types, some option codes MUST be included in the
    // Option Request option; see Table 4 for details.
    //
    // The Option Request option MUST NOT include the following options:
    //
    // -  Client Identifier (see Section 21.2)
    // -  Server Identifier (see Section 21.3)
    // -  IA_NA (see Section 21.4)
    // -  IA_TA (see Section 21.5)
    // -  IA_PD (see Section 21.21)
    // -  IA Address (see Section 21.6)
    // -  IA Prefix (see Section 21.22)
    // -  Option Request (this section)
    // -  Elapsed Time (see Section 21.9)
    // -  Preference (see Section 21.8)
    // -  Relay Message (see Section 21.10)
    // -  Authentication (see Section 21.11)
    // -  Server Unicast (see Section 21.12)
    // -  Status Code (see Section 21.13)
    // -  Rapid Commit (see Section 21.14)
    // -  User Class (see Section 21.15)
    // -  Vendor Class (see Section 21.16)
    // -  Interface-Id (see Section 21.18)
    // -  Reconfigure Message (see Section 21.19)
    // -  Reconfigure Accept (see Section 21.20)
    //
    // Other top-level options MUST appear in the Option Request option or
    // they will not be sent by the server.  Only top-level options MAY
    // appear in the Option Request option.  Options encapsulated in a
    // container option SHOULD NOT appear in an Option Request option; see
    // [RFC7598] for an example of container options.  However, options MAY
    // be defined that specify exceptions to this restriction on including
    // encapsulated options in an Option Request option.  For example, the
    // Option Request option MAY be used to signal support for a feature
    // even when that option is encapsulated, as in the case of the Prefix
    // Exclude option [RFC6603].  See Table 4.
    pub const OPT_ORO: u16 = 6;

    // The Preference option is sent by a server to a client to control the
    // selection of a server by the client.
 
    // The format of the Preference option is:
 
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |       OPTION_PREFERENCE       |          option-len           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |  pref-value   |
    //    +-+-+-+-+-+-+-+-+
 
    //                  Figure 19: Preference Option Format
 
    //    option-code          OPTION_PREFERENCE (7).
 
    //    option-len           1.
 
    //    pref-value           The preference value for the server in this
    //                         message.  A 1-octet unsigned integer.
 
    // A server MAY include a Preference option in an Advertise message to
    // control the selection of a server by the client.  See Section 18.2.9
    // for information regarding the use of the Preference option by the
    // client and the interpretation of the Preference option data value.
    pub const OPT_PREFERENCE: u16 = 7;

    //    0                   1                   2                   3
    //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |      OPTION_ELAPSED_TIME      |           option-len          |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |          elapsed-time         |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                Figure 20: Elapsed Time Option Format
    //
    //                option-code          OPTION_ELAPSED_TIME (8).
    //
    //                option-len           2.
    //       
    //                elapsed-time         The amount of time since the client began its
    //                                     current DHCP transaction.  This time is
    //                                     expressed in hundredths of a second
    //                                     (10^-2 seconds).  A 2-octet field containing
    //                                     an unsigned integer.
    //       
    //             A client MUST include an Elapsed Time option in messages to indicate
    //             how long the client has been trying to complete a DHCP message
    //             exchange.  The elapsed time is measured from the time at which the
    //             client sent the first message in the message exchange, and the
    //             elapsed-time field is set to 0 in the first message in the message
    //             exchange.  Servers and relay agents use the data value in this option
    //             as input to policy that controls how a server responds to a client
    //             message.  For example, the Elapsed Time option allows a secondary
    //             DHCP server to respond to a request when a primary server has not
    //             answered in a reasonable time.  The elapsed-time value is a 16-bit
    //             (2-octet) unsigned integer.  The client uses the value 0xffff to
    //             represent any elapsed-time values greater than the largest time value
    //             that can be represented in the Elapsed Time option.
    pub const OPT_ELAPSED_TIME: u16 = 8;

    // The Relay Message option carries a DHCP message in a Relay-forward or
    // Relay-reply message.
    //
    // The format of the Relay Message option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |        OPTION_RELAY_MSG       |           option-len          |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                                                               |
    //    .                       DHCP-relay-message                      .
    //    .                                                               .
    //    .                                                               .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                Figure 21: Relay Message Option Format
    //
    //                option-code          OPTION_RELAY_MSG (9).
    //
    //                option-len           Length of DHCP-relay-message field.
    //
    //                DHCP-relay-message   In a Relay-forward message, the received
    //                                     message, relayed verbatim to the next relay
    //                                     agent or server; in a Relay-reply message,
    //                                     the message to be copied and relayed to the
    //                                     relay agent or client whose address is in the
    //                                     peer-address field of the Relay-reply
    //                                     message.  The length, in octets, is specified
    //                                     by option-len.
    pub const OPT_RELAY_MSG: u16 = 9;

    // The Authentication option carries authentication information to
    // authenticate the identity and contents of DHCP messages.  The use of
    // the Authentication option is described in Section 20.  The delayed
    // authentication protocol, defined in [RFC3315], has been obsoleted by
    // this document, due to lack of usage (see Section 25).  The format of
    // the Authentication option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |          OPTION_AUTH          |          option-len           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |   protocol    |   algorithm   |      RDM      |               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
    //    |                                                               |
    //    |          replay detection (64 bits)           +-+-+-+-+-+-+-+-+
    //    |                                               |               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
    //    .                   authentication information                  .
    //    .                       (variable length)                       .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                Figure 22: Authentication Option Format
    //
    //    option-code                  OPTION_AUTH (11).
    //    option-len                   11 + length of authentication
    //                                 information field.
    //    protocol                     The authentication protocol used in
    //                                 this Authentication option.  A
    //                                 1-octet unsigned integer.
    pub const OPT_AUTH: u16 = 11;

    // The server sends this option to a client to indicate to the client
    // that it is allowed to unicast messages to the server.  The format of
    // the Server Unicast option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |          OPTION_UNICAST       |        option-len             |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                                                               |
    //    |                       server-address                          |
    //    |                                                               |
    //    |                                                               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                Figure 23: Server Unicast Option Format
    //
    //    option-code          OPTION_UNICAST (12).
    //
    //    option-len           16.
    //
    //    server-address       The 128-bit address to which the client
    //                         should send messages delivered using unicast.
    //                         The server specifies in the server-address field the address to which
    //                         the client is to send unicast messages.  When a client receives this
    //                         option, where permissible and appropriate the client sends messages
    //                         directly to the server using the address specified in the
    //                         server-address field of the option.
    //            
    //                         When the server sends a Server Unicast option to the client, some
    //                         messages from the client will not be relayed by relay agents and will
    //                         not include relay agent options from the relay agents.  Therefore, a
    //                         server should only send a Server Unicast option to a client when
    //                         relay agents are not sending relay agent options.  A DHCP server
    //                         rejects any messages sent inappropriately using unicast to ensure
    //                         that messages are relayed by relay agents when relay agent options
    //                         are in use.
    //                   
    //                         Details about when the client may send messages to the server using
    //                         unicast are provided in Section 18. 
    pub const OPT_UNICAST: u16 = 12;

    // This option returns a status indication related to the DHCP message
    // or option in which it appears.  The format of the Status Code
    // option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |       OPTION_STATUS_CODE      |         option-len            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |          status-code          |                               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
    //    .                                                               .
    //    .                        status-message                         .
    //    .                                                               .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                 Figure 24: Status Code Option Format
    //    option-code          OPTION_STATUS_CODE (13).
    //    option-len           2 + length of status-message field.
    //    status-code          The numeric code for the status encoded in
    //                         this option.  A 2-octet field containing an
    //                         unsigned integer.
    //                         status-message       A UTF-8 encoded [RFC3629] text string
    //                         suitable for display to an end user.
    //                         MUST NOT be null-terminated.  A
    //                         variable-length field (2 octets less than the
    //                         value in the option-len field).
    //
    // A Status Code option may appear in the "options" field of a DHCP
    // message and/or in the "options" field of another option.  If the
    // Status Code option does not appear in a message in which the option
    // could appear, the status of the message is assumed to be Success.
    //
    // The status-code values previously defined by [RFC3315] and
    // [RFC3633] are:
    //
    // +---------------+------+--------------------------------------------+
    // | Name          | Code | Description                                |
    // +---------------+------+--------------------------------------------+
    // | Success       |    0 | Success.                                   |
    // |               |      |                                            |
    // | UnspecFail    |    1 | Failure, reason unspecified; this status   |
    // |               |      | code is sent by either a client or a       |
    // |               |      | server to indicate a failure not           |
    // |               |      | explicitly specified in this document.     |
    // |               |      |                                            |
    // | NoAddrsAvail  |    2 | The server has no addresses available to   |
    // |               |      | assign to the IA(s).                       |
    // |               |      |                                            |
    // | NoBinding     |    3 | Client record (binding) unavailable.       |
    // |               |      |                                            |
    // | NotOnLink     |    4 | The prefix for the address is not          |
    // |               |      | appropriate for the link to which the      |
    // |               |      | client is attached.                        |
    // |               |      |                                            |
    // | UseMulticast  |    5 | Sent by a server to a client to force the  |
    // |               |      | client to send messages to the server      |
    // |               |      | using the                                  |
    // |               |      | All_DHCP_Relay_Agents_and_Servers          |
    // |               |      | multicast address.                         |
    // |               |      |                                            |
    // | NoPrefixAvail |    6 | The server has no prefixes available to    |
    // |               |      | assign to the IA_PD(s).                    |
    // +---------------+------+--------------------------------------------+
    //
    //                   Table 3: Status Code Definitions
    //
    // See the "Status Codes" registry at <https://www.iana.org/assignments/
    // dhcpv6-parameters> for the current list of status codes.
    pub const OPT_STATUS_CODE: u16 = 13;

    // The Rapid Commit option is used to signal the use of the two-message
    // exchange for address assignment.  The format of the Rapid Commit
    // option is:
 
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |      OPTION_RAPID_COMMIT      |         option-len            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
    //                 Figure 25: Rapid Commit Option Format
 
    //    option-code          OPTION_RAPID_COMMIT (14).
 
    //    option-len           0.
 
    // A client MAY include this option in a Solicit message if the client
    // is prepared to perform the Solicit/Reply message exchange described
    // in Section 18.2.1.
 
    // A server MUST include this option in a Reply message sent in response
    // to a Solicit message when completing the Solicit/Reply message
    // exchange.
    pub const OPT_RAPID_COMMIT: u16 = 14;

    // The User Class option is used by a client to identify the type or
    // category of users or applications it represents.
    //
    // The format of the User Class option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |       OPTION_USER_CLASS       |          option-len           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    .                                                               .
    //    .                          user-class-data                      .
    //    .                                                               .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                  Figure 26: User Class Option Format
    //    option-code          OPTION_USER_CLASS (15).
    //    option-len           Length of user-class-data field.
    //    user-class-data      The user classes carried by the client.  The
    //                         length, in octets, is specified by
    //                         option-len.
    //
    // The information contained in the data area of this option is
    // contained in one or more opaque fields that represent the user class
    // or classes of which the client is a member.  A server selects
    // configuration information for the client based on the classes
    // identified in this option.  For example, the User Class option can be
    // used to configure all clients of people in the accounting department
    // with a different printer than clients of people in the marketing
    // department.  The user class information carried in this option MUST
    // be configurable on the client.
    //
    // The data area of the User Class option MUST contain one or more
    // instances of user-class-data information.  Each instance of
    // user-class-data is formatted as follows:
    //
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+
    //    |        user-class-len         |          opaque-data          |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+
    //
    //              Figure 27: Format of user-class-data Field
    //
    // The user-class-len field is 2 octets long and specifies the length of
    // the opaque user-class-data in network byte order.
    //
    // A server interprets the classes identified in this option according
    // to its configuration to select the appropriate configuration
    // information for the client.  A server may use only those user classes
    // that it is configured to interpret in selecting configuration
    // information for a client and ignore any other user classes.  In
    // response to a message containing a User Class option, a server may
    // include a User Class option containing those classes that were
    // successfully interpreted by the server so that the client can be
    // informed of the classes interpreted by the server.
    pub const OPT_USER_CLASS: u16 = 15;

    // This option is used by a client to identify the vendor that
    // manufactured the hardware on which the client is running.  The
    // information contained in the data area of this option is contained in
    // one or more opaque fields that identify details of the hardware
    // configuration.  The format of the Vendor Class option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |      OPTION_VENDOR_CLASS      |           option-len          |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                       enterprise-number                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    .                                                               .
    //    .                       vendor-class-data                       .
    //    .                             . . .                             .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                 Figure 28: Vendor Class Option Format
    //
    //    option-code          OPTION_VENDOR_CLASS (16).
    //    option-len           4 + length of vendor-class-data field.
    //    enterprise-number    The vendor's registered Enterprise Number as
    //                         maintained by IANA [IANA-PEN].  A 4-octet
    //                         field containing an unsigned integer.
    //    vendor-class-data    The hardware configuration of the node on
    //                         which the client is running.  A
    //                         variable-length field (4 octets less than the
    //                         value in the option-len field).
    // The vendor-class-data field is composed of a series of separate
    // items, each of which describes some characteristic of the client's
    // hardware configuration.  Examples of vendor-class-data instances
    // might include the version of the operating system the client is
    // running or the amount of memory installed on the client.
    //
    // Each instance of vendor-class-data is formatted as follows:
    //
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+
    //    |       vendor-class-len        |          opaque-data          |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+
    //
    //             Figure 29: Format of vendor-class-data Field
    //
    // The vendor-class-len field is 2 octets long and specifies the length
    // of the opaque vendor-class-data in network byte order.
    //
    // Servers and clients MUST NOT include more than one instance of
    // OPTION_VENDOR_CLASS with the same Enterprise Number.  Each instance
    // of OPTION_VENDOR_CLASS can carry multiple vendor-class-data
    // instances.
    pub const OPT_VENDOR_CLASS: u16 = 16;

    // This option is used by clients and servers to exchange vendor-
    // specific information.
    //
    // The format of the Vendor-specific Information option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |      OPTION_VENDOR_OPTS       |           option-len          |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                       enterprise-number                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    .                                                               .
    //    .                       vendor-option-data                      .
    //    .                                                               .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //         Figure 30: Vendor-specific Information Option Format
    //
    //    option-code          OPTION_VENDOR_OPTS (17).
    //    option-len           4 + length of vendor-option-data field.
    //    enterprise-number    The vendor's registered Enterprise Number as
    //                         maintained by IANA [IANA-PEN].  A 4-octet
    //                         field containing an unsigned integer.
    //    vendor-option-data   Vendor options, interpreted by
    //                         vendor-specific code on the clients and
    //                         servers.  A variable-length field (4 octets
    //                         less than the value in the option-len field).
    //
    // The definition of the information carried in this option is vendor
    // specific.  The vendor is indicated in the enterprise-number field.
    // Use of vendor-specific information allows enhanced operation,
    // utilizing additional features in a vendor's DHCP implementation.  A
    // DHCP client that does not receive requested vendor-specific
    // information will still configure the node's IPv6 stack to be
    // functional.
    //
    // The vendor-option-data field MUST be encoded as a sequence of
    // code/length/value fields of format identical to the DHCP options (see
    // Section 21.1).  The sub-option codes are defined by the vendor
    // identified in the enterprise-number field and are not managed by
    // IANA.  Each of the sub-options is formatted as follows:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     |          sub-opt-code         |         sub-option-len        |
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     .                                                               .
    //     .                        sub-option-data                        .
    //     .                                                               .
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                 Figure 31: Vendor-specific Options Format
    //
    //     sub-opt-code         The code for the sub-option.  A 2-octet
    //                         field.
    //     sub-option-len       An unsigned integer giving the length of the
    //                         sub-option-data field in this sub-option in
    //                         octets.  A 2-octet field.
    //     sub-option-data      The data area for the sub-option.  The
    //                         length, in octets, is specified by
    //                         sub-option-len.
    // Multiple instances of the Vendor-specific Information option may
    // appear in a DHCP message.  Each instance of the option is interpreted
    // according to the option codes defined by the vendor identified by the
    // Enterprise Number in that option.  Servers and clients MUST NOT send
    // more than one instance of the Vendor-specific Information option with
    // the same Enterprise Number.  Each instance of the Vendor-specific
    // Information option MAY contain multiple sub-options.
    //
    // A client that is interested in receiving a Vendor-specific
    // Information option:
    //
    // -  MUST specify the Vendor-specific Information option in an Option
    //    Request option.
    //
    // -  MAY specify an associated Vendor Class option (see Section 21.16).
    //
    // -  MAY specify the Vendor-specific Information option with
    //    appropriate data.
    //
    // Servers only return the Vendor-specific Information options if
    // specified in Option Request options from clients and:
    //
    // -  MAY use the Enterprise Numbers in the associated Vendor Class
    //    options to restrict the set of Enterprise Numbers in the
    //    Vendor-specific Information options returned.
    //
    // -  MAY return all configured Vendor-specific Information options.
    //
    // -  MAY use other information in the packet or in its configuration to
    //    determine which set of Enterprise Numbers in the Vendor-specific
    //    Information options to return.
    pub const OPT_SUB_OPT_CODE: u16 = 17;

    //     The relay agent MAY send the Interface-Id option to identify the
    //     interface on which the client message was received.  If a relay agent
    //     receives a Relay-reply message with an Interface-Id option, the relay
    //     agent relays the message to the client through the interface
    //     identified by the option.
    //  
    //     The format of the Interface-Id option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     |      OPTION_INTERFACE_ID      |         option-len            |
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     .                                                               .
    //     .                         interface-id                          .
    //     .                                                               .
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                 Figure 32: Interface-Id Option Format
    //
    //     option-code          OPTION_INTERFACE_ID (18).
    //     option-len           Length of interface-id field.
    //     interface-id         An opaque value of arbitrary length generated
    //                         by the relay agent to identify one of the
    //                         relay agent's interfaces.  The length, in
    //                         octets, is specified by option-len.
    //
    // The server MUST copy the Interface-Id option from the Relay-forward
    // message into the Relay-reply message the server sends to the relay
    // agent in response to the Relay-forward message.  This option MUST NOT
    // appear in any message except a Relay-forward or Relay-reply message.
    //
    // Servers MAY use the interface-id field for parameter assignment
    // policies.  The interface-id value SHOULD be considered an opaque
    // value, with policies based on exact match only; that is, the
    // interface-id field SHOULD NOT be internally parsed by the server.
    // The interface-id value for an interface SHOULD be stable and remain
    // unchanged -- for example, after the relay agent is restarted; if the
    // interface-id value changes, a server will not be able to use it
    // reliably in parameter assignment policies.
    pub const OPT_INTERFACE_ID: u16 = 18;

    // A server includes a Reconfigure Message option in a Reconfigure
    // message to indicate to the client whether the client responds with a
    // Renew message, a Rebind message, or an Information-request message.
    // The format of the Reconfigure Message option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |      OPTION_RECONF_MSG        |         option-len            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |    msg-type   |
    //    +-+-+-+-+-+-+-+-+
    //
    //             Figure 33: Reconfigure Message Option Format
    //
    //    option-code          OPTION_RECONF_MSG (19).
    //    option-len           1.
    //    msg-type             5 for Renew message, 6 for Rebind message,
    //                         11 for Information-request message.  A
    //                         1-octet unsigned integer.
    //
    // The Reconfigure Message option can only appear in a Reconfigure
    // message.
    pub const OPT_RECONF_MSG: u16 = 19;

    // A client uses the Reconfigure Accept option to announce to the server
    // whether the client is willing to accept Reconfigure messages, and a
    // server uses this option to tell the client whether or not to accept
    // Reconfigure messages.  In the absence of this option, the default
    // behavior is that the client is unwilling to accept Reconfigure
    // messages.  The format of the Reconfigure Accept option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |     OPTION_RECONF_ACCEPT      |         option-len            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //              Figure 34: Reconfigure Accept Option Format
    //
    //    option-code          OPTION_RECONF_ACCEPT (20).
    //    option-len           0.
    pub const OPT_RECONF_ACCEPT: u16 = 20;

    // The DNS Recursive Name Server option provides a list of one or more
    // IPv6 addresses of DNS recursive name servers to which a client's DNS
    // resolver MAY send DNS queries [1].  The DNS servers are listed in the
    // order of preference for use by the client resolver.
    //
    // The format of the DNS Recursive Name Server option is:
    //
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      OPTION_DNS_SERVERS       |         option-len            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // |            DNS-recursive-name-server (IPv6 address)           |
    // |                                                               |
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // |            DNS-recursive-name-server (IPv6 address)           |
    // |                                                               |
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                              ...                              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // option-code:               OPTION_DNS_SERVERS (23)
    //
    // option-len:                Length of the list of DNS recursive name
    //                            servers in octets; must be a multiple of
    //                            16
    //
    // DNS-recursive-name-server: IPv6 address of DNS recursive name server
    pub const OPT_DNS_SERVERS: u16 = 23;

    // The Domain Search List option specifies the domain search list the
    // client is to use when resolving hostnames with DNS.  This option does
    // not apply to other name resolution mechanisms.
    //
    //     The format of the Domain Search List option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     |      OPTION_DOMAIN_LIST       |         option-len            |
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     |                          searchlist                           |
    //     |                              ...                              |
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // option-code:  OPTION_DOMAIN_LIST (24)
    //
    // option-len:   Length of the 'searchlist' field in octets
    //
    // searchlist:   The specification of the list of domain names in the
    //                 Domain Search List
    //
    // The list of domain names in the 'searchlist' MUST be encoded as
    // specified in section "Representation and use of domain names" of RFC
    //
    // So that domain names may be encoded uniformly, a domain name or a
    // list of domain names is encoded using the technique described in
    // section 3.1 of RFC 1035 [10].  A domain name, or list of domain
    // names, in DHCP MUST NOT be stored in compressed form, as described in
    // section 4.1.4 of RFC 1035.
    //
    // Domain names in messages are expressed in terms of a sequence of labels.
    // Each label is represented as a one octet length field followed by that
    // number of octets.  Since every domain name ends with the null label of
    // the root, a domain name is terminated by a length byte of zero.  The
    // high order two bits of every length octet must be zero, and the
    // remaining six bits of the length field limit the label to 63 octets or
    // less.
    //
    // To simplify implementations, the total length of a domain name (i.e.,
    // label octets and label length octets) is restricted to 255 octets or
    // less.
    //
    // Although labels can contain any 8 bit values in octets that make up a
    // label, it is strongly recommended that labels follow the preferred
    // syntax described elsewhere in this memo, which is compatible with
    // existing host naming conventions.  Name servers and resolvers must
    // compare labels in a case-insensitive manner (i.e., A=a), assuming ASCII
    // with zero parity.  Non-alphabetic codes must match exactly.
    pub const OPT_DOMAIN_LIST: u16 = 24;

    // The IA_PD option is used to carry a prefix delegation identity
    // association, the parameters associated with the IA_PD, and the
    // prefixes associated with it.  The format of the IA_PD option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |         OPTION_IA_PD          |           option-len          |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                         IAID (4 octets)                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                              T1                               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                              T2                               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    .                                                               .
    //    .                          IA_PD-options                        .
    //    .                                                               .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //  Figure 35: Identity Association for Prefix Delegation Option Format
    //
    //    option-code          OPTION_IA_PD (25).
    //    option-len           12 + length of IA_PD-options field.
    //    IAID                 The unique identifier for this IA_PD; the
    //                         IAID must be unique among the identifiers for
    //                         all of this client's IA_PDs.  The number
    //                         space for IA_PD IAIDs is separate from the
    //                         number space for other IA option types (i.e.,
    //                         IA_NA and IA_TA).  A 4-octet field containing
    //                         an unsigned integer.
    //    T1                   The time interval after which the client
    //                         should contact the server from which the
    //                         prefixes in the IA_PD were obtained to extend
    //                         the lifetimes of the prefixes delegated to
    //                         the IA_PD; T1 is a time duration relative to
    //                         the message reception time expressed in units
    //                         of seconds.  A 4-octet field containing an
    //                         unsigned integer.
    //    T2                   The time interval after which the client
    //                         should contact any available server to extend
    //                         the lifetimes of the prefixes assigned to the
    //                         IA_PD; T2 is a time duration relative to the
    //                         message reception time expressed in units of
    //                         seconds.  A 4-octet field containing an
    //                         unsigned integer.
    //     IA_PD-options        Options associated with this IA_PD.  A
    //                         variable-length field (12 octets less than
    //                         the value in the option-len field).
    //
    // The IA_PD-options field encapsulates those options that are specific
    // to this IA_PD.  For example, all of the IA Prefix options (see
    // Section 21.22) carrying the prefixes associated with this IA_PD are
    // in the IA_PD-options field.
    //
    // An IA_PD option may only appear in the options area of a DHCP
    // message.  A DHCP message may contain multiple IA_PD options (though
    // each must have a unique IAID).
    //
    // The status of any operations involving this IA_PD is indicated in a
    // Status Code option (see Section 21.13) in the IA_PD-options field.
    //
    // Note that an IA_PD has no explicit "lifetime" or "lease length" of
    // its own.  When the valid lifetimes of all of the prefixes in an IA_PD
    // have expired, the IA_PD can be considered as having expired.  T1 and
    // T2 fields are included to give the server explicit control over when
    // a client should contact the server about a specific IA_PD.
    //
    // In a message sent by a client to a server, the T1 and T2 fields
    // SHOULD be set to 0.  The server MUST ignore any values in these
    // fields in messages received from a client.
    //
    // In a message sent by a server to a client, the client MUST use the
    // values in the T1 and T2 fields for the T1 and T2 timers, unless
    // values in those fields are 0.  The values in the T1 and T2 fields are
    // the number of seconds until T1 and T2.
    //
    // The server selects the T1 and T2 times to allow the client to extend
    // the lifetimes of any prefixes in the IA_PD before the lifetimes
    // expire, even if the server is unavailable for some short period of
    // time.  Recommended values for T1 and T2 are 0.5 and 0.8 times the
    // shortest preferred lifetime of the prefixes in the IA_PD that the
    // server is willing to extend, respectively.  If the time at which the
    // prefixes in an IA_PD are to be renewed is to be left to the
    // discretion of the client, the server sets T1 and T2 to 0.  The client
    // MUST follow the rules defined in Section 14.2.
    //
    // If a client receives an IA_PD with T1 greater than T2 and both T1 and
    // T2 are greater than 0, the client discards the IA_PD option and
    // processes the remainder of the message as though the server had not
    // included the IA_PD option.
    pub const OPT_IA_PD: u16 = 25;

    // The IA Prefix option is used to specify a prefix associated with an
    // IA_PD.  The IA Prefix option must be encapsulated in the
    // IA_PD-options field of an IA_PD option (see Section 21.21).
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |        OPTION_IAPREFIX        |           option-len          |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                      preferred-lifetime                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                        valid-lifetime                         |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    | prefix-length |                                               |
    //    +-+-+-+-+-+-+-+-+          IPv6-prefix                          |
    //    |                           (16 octets)                         |
    //    |                                                               |
    //    |                                                               |
    //    |                                                               |
    //    |               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |               |                                               .
    //    +-+-+-+-+-+-+-+-+                                               .
    //    .                       IAprefix-options                        .
    //    .                                                               .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                  Figure 36: IA Prefix Option Format
    //
    //    option-code          OPTION_IAPREFIX (26).
    //    option-len           25 + length of IAprefix-options field.
    //    preferred-lifetime   The preferred lifetime for the prefix in the
    //                         option, expressed in units of seconds.  A
    //                         value of 0xffffffff represents "infinity"
    //                         (see Section 7.7).  A 4-octet field
    //                         containing an unsigned integer.
    //    valid-lifetime       The valid lifetime for the prefix in the
    //                         option, expressed in units of seconds.  A
    //                         value of 0xffffffff represents "infinity".  A
    //                         4-octet field containing an unsigned integer.
    //     prefix-length        Length for this prefix in bits.  A 1-octet
    //                         unsigned integer.
    //     IPv6-prefix          An IPv6 prefix.  A 16-octet field.
    //     IAprefix-options     Options associated with this prefix.  A
    //                         variable-length field (25 octets less than
    //                         the value in the option-len field).
    //
    // In a message sent by a client to a server, the preferred-lifetime and
    // valid-lifetime fields SHOULD be set to 0.  The server MUST ignore any
    // received values in these lifetime fields.
    //
    // The client SHOULD NOT send an IA Prefix option with 0 in the
    // "prefix-length" field (and an unspecified value (::) in the
    // "IPv6-prefix" field).  A client MAY send a non-zero value in the
    // "prefix-length" field and the unspecified value (::) in the
    // "IPv6-prefix" field to indicate a preference for the size of the
    // prefix to be delegated.  See [RFC8168] for further details on prefix-
    // length hints.
    //
    // The client MUST discard any prefixes for which the preferred lifetime
    // is greater than the valid lifetime.
    //
    // The values in the preferred-lifetime and valid-lifetime fields are
    // the number of seconds remaining in each lifetime.  See
    // Section 18.2.10.1 for more details on how these values are used for
    // delegated prefixes.
    //
    // As per Section 7.7, the value of 0xffffffff for the preferred
    // lifetime or the valid lifetime is taken to mean "infinity" and should
    // be used carefully.
    //
    // An IA Prefix option may appear only in an IA_PD option.  More than
    // one IA Prefix option can appear in a single IA_PD option.
    //
    // The status of any operations involving this IA Prefix option is
    // indicated in a Status Code option (see Section 21.13) in the
    // IAprefix-options field.
    pub const OPT_IA_PREFIX: u16 = 26;

    // This option is requested by clients and returned by servers to
    // specify an upper bound for how long a client should wait before
    // refreshing information retrieved from a DHCP server.  It is only used
    // in Reply messages in response to Information-request messages.  In
    // other messages, there will usually be other information that
    // indicates when the client should contact the server, e.g., T1/T2
    // times and lifetimes.  This option is useful when the configuration
    // parameters change or during a renumbering event, as clients running
    // in the stateless mode will be able to update their configuration.
    //
    // The format of the Information Refresh Time option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |OPTION_INFORMATION_REFRESH_TIME|         option-len            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                   information-refresh-time                    |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //           Figure 37: Information Refresh Time Option Format
    //
    //    option-code                OPTION_INFORMATION_REFRESH_TIME (32).
    //    option-len                 4.
    //    information-refresh-time   Time duration relative to the current
    //                               time, expressed in units of seconds.  A
    //                               4-octet field containing an unsigned
    //                               integer.
    //
    // A DHCP client MUST request this option in the Option Request option
    // (see Section 21.7) when sending Information-request messages.  A
    // client MUST NOT request this option in the Option Request option in
    // any other messages.
    //
    // A server sending a Reply to an Information-request message SHOULD
    // include this option if it is requested in the Option Request option
    // of the Information-request.  The option value MUST NOT be smaller
    // than IRT_MINIMUM.  This option MUST only appear in the top-level
    // options area of Reply messages.
    //
    // If the Reply to an Information-request message does not contain this
    // option, the client MUST behave as if the option with the value
    // IRT_DEFAULT was provided.
    // A client MUST use the refresh time IRT_MINIMUM if it receives the
    // option with a value less than IRT_MINIMUM.
    //
    // As per Section 7.7, the value 0xffffffff is taken to mean "infinity"
    // and implies that the client should not refresh its configuration data
    // without some other trigger (such as detecting movement to a new
    // link).
    //
    // If a client contacts the server to obtain new data or refresh some
    // existing data before the refresh time expires, then it SHOULD also
    // refresh all data covered by this option.
    //
    // When the client detects that the refresh time has expired, it SHOULD
    // try to update its configuration data by sending an
    // Information-request as specified in Section 18.2.6, except that the
    // client MUST delay sending the first Information-request by a random
    // amount of time between 0 and INF_MAX_DELAY.
    //
    // A client MAY have a maximum value for the refresh time, where that
    // value is used whenever the client receives this option with a value
    // higher than the maximum.  This also means that the maximum value is
    // used when the received value is "infinity".  A maximum value might
    // make the client less vulnerable to attacks based on forged DHCP
    // messages.  Without a maximum value, a client may be made to use wrong
    // information for a possibly infinite period of time.  There may,
    // however, be reasons for having a very long refresh time, so it may be
    // useful for this maximum value to be configurable.
    pub const OPT_INFORMATION_REFRESH_TIME: u16 = 32;

    // A DHCP server sends the SOL_MAX_RT option to a client to override the
    // default value of SOL_MAX_RT.  The value of SOL_MAX_RT in the option
    // replaces the default value defined in Section 7.6.  One use for the
    // SOL_MAX_RT option is to set a higher value for SOL_MAX_RT; this
    // reduces the Solicit traffic from a client that has not received a
    // response to its Solicit messages.
    //
    // The format of the SOL_MAX_RT option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |      OPTION_SOL_MAX_RT        |         option-len            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                       SOL_MAX_RT value                        |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                  Figure 38: SOL_MAX_RT Option Format
    //
    //     option-code          OPTION_SOL_MAX_RT (82).
    //     option-len           4.
    //     SOL_MAX_RT value     Overriding value for SOL_MAX_RT in seconds;
    //                         MUST be in this range: 60 <= "value" <= 86400
    //                         (1 day).  A 4-octet field containing an
    //                         unsigned integer.
    //
    // A DHCP client MUST include the SOL_MAX_RT option code in any Option
    // Request option (see Section 21.7) it sends in a Solicit message.
    //
    // The DHCP server MAY include the SOL_MAX_RT option in any response it
    // sends to a client that has included the SOL_MAX_RT option code in an
    // Option Request option.  The SOL_MAX_RT option is sent as a top-level
    // option in the message to the client.
    //
    // A DHCP client MUST ignore any SOL_MAX_RT option values that are less
    // than 60 or more than 86400.
    //
    // If a DHCP client receives a message containing a SOL_MAX_RT option
    // that has a valid value for SOL_MAX_RT, the client MUST set its
    // internal SOL_MAX_RT parameter to the value contained in the
    // SOL_MAX_RT option.  This value of SOL_MAX_RT is then used by the
    // retransmission mechanism defined in Sections 15 and 18.2.1.
    //
    // The purpose of this mechanism is to give network administrators a way
    // to avoid excessive DHCP traffic if all DHCP servers become
    // unavailable.  Therefore, this value is expected to be retained for as
    // long as practically possible.
    //
    // An updated SOL_MAX_RT value applies only to the network interface on
    // which the client received the SOL_MAX_RT option.
    pub const OPT_MAX_RT: u16 = 82;

    // A DHCP server sends the INF_MAX_RT option to a client to override the
    // default value of INF_MAX_RT.  The value of INF_MAX_RT in the option
    // replaces the default value defined in Section 7.6.  One use for the
    // INF_MAX_RT option is to set a higher value for INF_MAX_RT; this
    // reduces the Information-request traffic from a client that has not
    // received a response to its Information-request messages.
    //
    //     The format of the INF_MAX_RT option is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     |      OPTION_INF_MAX_RT        |         option-len            |
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     |                       INF_MAX_RT value                        |
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                     Figure 39: INF_MAX_RT Option Format
    //     option-code          OPTION_INF_MAX_RT (83).
    //     option-len           4.
    //     INF_MAX_RT value     Overriding value for INF_MAX_RT in seconds;
    //                         MUST be in this range: 60 <= "value" <= 86400
    //                         (1 day).  A 4-octet field containing an
    //                         unsigned integer.
    //
    // A DHCP client MUST include the INF_MAX_RT option code in any Option
    // Request option (see Section 21.7) it sends in an Information-request
    // message.
    //
    // The DHCP server MAY include the INF_MAX_RT option in any response it
    // sends to a client that has included the INF_MAX_RT option code in an
    // Option Request option.  The INF_MAX_RT option is a top-level option
    // in the message to the client.
    //
    // A DHCP client MUST ignore any INF_MAX_RT option values that are less
    // than 60 or more than 86400.
    //
    // If a DHCP client receives a message containing an INF_MAX_RT option
    // that has a valid value for INF_MAX_RT, the client MUST set its
    // internal INF_MAX_RT parameter to the value contained in the
    // INF_MAX_RT option.  This value of INF_MAX_RT is then used by the
    // retransmission mechanism defined in Sections 15 and 18.2.6.
    //
    // An updated INF_MAX_RT value applies only to the network interface on
    // which the client received the INF_MAX_RT option.
    pub const OPT_INF_MAX_RT: u16 = 83;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with DHCP packet structure.
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::OPTIONS.start {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Returns the transaction ID.
    ///
    /// The transaction ID (called `xid` in the specification) is a random number used to
    /// associate messages and responses between client and server. The number is chosen by
    /// the client.
    pub fn transaction_id(&self) -> u32 {
        let field = &self.buffer.as_ref()[field::XID];
        NetworkEndian::read_u24(field)
    }

    /// Return an iterator over the options.
    #[inline]
    pub fn options(&self) -> impl Iterator<Item = Dhcpv6Option<'_>> + '_ {
        parse_options(&self.buffer.as_ref()[field::OPTIONS])
    }
}

/// Return an iterator over the options.
#[inline]
pub fn parse_options(mut buf: &[u8]) -> impl Iterator<Item = Dhcpv6Option<'_>> + '_ {
    iter::from_fn(move || {
        while buf.len() >= 4 {
            let kind = NetworkEndian::read_u16(&buf);
            buf = &buf[2..];

            let len = NetworkEndian::read_u16(&buf) as usize;
            if buf.len() < 2 + len {
                return None;
            }

            let opt = Dhcpv6Option {
                kind,
                data: &buf[2..2 + len],
            };

            buf = &buf[2 + len..];
            return Some(opt);
        }
        return None;
    })
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Sets the message type.
    pub fn set_message_type(&mut self, value: MessageType) {
        let field = &mut self.buffer.as_mut()[field::MTYPE];
        *field = value.into();
    }

    /// Sets the transaction ID.
    ///
    /// The transaction ID (called `xid` in the specification) is a random number used to
    /// associate messages and responses between client and server. The number is chosen by
    /// the client.
    pub fn set_transaction_id(&mut self, value: u32) {
        let value = value & 0xff_ffff;
        let field = &mut self.buffer.as_mut()[field::XID];
        NetworkEndian::write_u24(field, value)
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return a pointer to the options.
    #[inline]
    pub fn options_mut(&mut self) -> Dhcpv6OptionWriter<'_> {
        Dhcpv6OptionWriter::new(&mut self.buffer.as_mut()[field::OPTIONS])
    }
}

// All DHCP messages sent between clients and servers share an identical
// fixed-format header and a variable-format area for options.
// 
// All values in the message header and in options are in network byte
// order.
// 
// Options are stored serially in the "options" field, with no padding
// between the options.  Options are byte-aligned but are not aligned in
// any other way (such as on 2-byte or 4-byte boundaries).
// 
// The following diagram illustrates the format of DHCP messages sent
// between clients and servers:
//
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |    msg-type   |               transaction-id                  |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                                                               |
//    .                            options                            .
//    .                 (variable number and length)                  .
//    |                                                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//                Figure 2: Client/Server Message Format
//
//    msg-type             Identifies the DHCP message type; the
//                         available message types are listed in
//                         Section 7.3.  A 1-octet field.
//    transaction-id       The transaction ID for this message exchange.
//                         A 3-octet field.
//    options              Options carried in this message; options are
//                         described in Section 21.  A variable-length
//                         field (4 octets less than the size of the
//                         message).
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Repr<'a> {
    /// This field is also known as `op` in the RFC. It indicates the type of DHCP message this
    /// packet represents.
    pub message_type: MessageType,
    /// This field is also known as `xid` in the RFC. It is a random number chosen by the client,
    /// used by the client and server to associate messages and responses between a client and a
    /// server.
    /// Note: Only the first 24bits of this ID are actually used
    pub transaction_id: u32,
    /// This field represents the client ID
    pub client_id: Option<&'a [u8]>,
    /// This field represents the client ID
    pub server_id: Option<&'a [u8]>,
    /// The elapsed time in hundreds of a second
    pub elapsed_time: Option<u16>,
    /// Used for the clients to request a certain set of options from the DHCPv6 server
    pub request_options: Option<Vec<u16, MAX_REQUEST_OPTIONS>>,
    /// Non-temporary addresses
    pub ia_na: Option<ReprIaNa<'a>>,
    /// Temporary addresses
    pub ia_ta: Option<ReprIaTa<'a>>,
    /// DNS Servers
    pub dns_servers: Option<ReprDnsServers>,
    /// When returned from [`Repr::parse`], this field will be `None`.
    /// However, when calling [`Repr::emit`], this field should contain only
    /// additional DHCP options not known to smoltcp.
    pub additional_options: &'a [Dhcpv6Option<'a>],
}

impl<'a> Repr<'a> {
    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        let mut len = field::OPTIONS.start;
        
        if let Some(id) = self.client_id.as_ref() {
            len += 4 + id.len();
        }
        if let Some(id) = self.server_id.as_ref() {
            len += 4 + id.len();
        }
        if let Some(_) = self.elapsed_time.as_ref() {
            len += 4 + 2;
        }
        if let Some(ia) = self.ia_na.as_ref() {
            len += 4 + ia.data_len();
        }
        if let Some(ia) = self.ia_ta.as_ref() {
            len += 4 + ia.data_len();
        }
        if let Some(dns) = self.dns_servers.as_ref() {
            len += 4 + dns.data_len();
        }
        if let Some(options) = self.request_options.as_ref() {
            len += 4;
            for _ in options {
                len += 2;
            }
        }
        for opt in self.additional_options {
            len += 4 + opt.data.len()
        }

        len
    }

    /// Parse a DHCP packet and return a high-level representation.
    pub fn parse<T>(packet: &'a Packet<&'a T>) -> Result<Self>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let transaction_id = packet.transaction_id();

        let message_type = MessageType::from(packet.buffer.as_ref()[field::MTYPE]);
        let mut client_id = None;
        let mut server_id = None;
        let mut elapsed_time = None;
        let mut ia_na = None;
        let mut ia_ta = None;
        let mut dns_servers = None;
        let mut request_options = None;

        for option in packet.options() {
            let data = option.data;
            match (option.kind, data.len()) {
                (field::OPT_CLIENTID, _) => {
                    client_id = Some(data);
                }
                (field::OPT_SERVERID, _) => {
                    server_id = Some(data);
                }
                (field::OPT_ELAPSED_TIME, 2) => {
                    elapsed_time = Some(u16::from_be_bytes([data[0], data[1]]));
                }
                (field::OPT_IA_NA, _) => {
                    ia_na = Some(
                        ReprIaNa::parse(data)?
                    );
                }
                (field::OPT_IA_TA, _) => {
                    ia_ta = Some(
                        ReprIaTa::parse(data)?
                    );
                }
                (field::OPT_DNS_SERVERS, _) => {
                    dns_servers = Some(
                        ReprDnsServers::parse(data)?
                    );
                }
                (field::OPT_ORO, _) => {
                    let mut options = Vec::new();
                    const REQUEST_OPTION_BYTE_LEN: usize = 4;
                    for chunk in data.chunks(REQUEST_OPTION_BYTE_LEN) {
                        options.push(NetworkEndian::read_u16(chunk)).ok();
                    }
                    request_options = Some(options);
                }
                _ => {}
            }
        }

        Ok(Repr {
            transaction_id,
            client_id,
            server_id,
            message_type,
            elapsed_time,
            request_options,
            ia_na,
            ia_ta,
            dns_servers,
            additional_options: &[],
        })
    }

    /// Emit a high-level representation into a Dynamic Host
    /// Configuration Protocol packet.
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>) -> Result<()>
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        packet.set_message_type(self.message_type);
        packet.set_transaction_id(self.transaction_id);

        {
            let mut dhcp_options = packet.options_mut();

            if let Some(val) = &self.client_id {
                dhcp_options.emit(Dhcpv6Option {
                    kind: field::OPT_CLIENTID,
                    data: val,
                })?;
            }

            if let Some(val) = &self.server_id {
                dhcp_options.emit(Dhcpv6Option {
                    kind: field::OPT_SERVERID,
                    data: val,
                })?;
            }

            if let Some(val) = &self.elapsed_time {
                dhcp_options.emit(Dhcpv6Option {
                    kind: field::OPT_ELAPSED_TIME,
                    data: &val.to_be_bytes(),
                })?;
            }

            if let Some(val) = &self.ia_na {
                val.emit(&mut dhcp_options)?;
            }

            if let Some(val) = &self.ia_ta {
                val.emit(&mut dhcp_options)?;
            }

            if let Some(dns) = &self.dns_servers {
                dns.emit(&mut dhcp_options)?;
            }

            if let Some(request_options) = &self.request_options {
                const REQUEST_OPTION_SIZE: usize = core::mem::size_of::<u16>();
                let mut options = [0; MAX_REQUEST_OPTIONS * REQUEST_OPTION_SIZE];

                let mut idx = 0;
                for opt in request_options.iter().cloned() {
                    NetworkEndian::write_u16(&mut options[idx..idx + REQUEST_OPTION_SIZE], opt);
                    idx += REQUEST_OPTION_SIZE;
                }
                dhcp_options.emit(Dhcpv6Option {
                    kind: field::OPT_ORO,
                    data: &options[..idx],
                })?;
            }

            for option in self.additional_options {
                dhcp_options.emit(*option)?;
            }
        }

        Ok(())
    }

    pub fn add_request_option(&mut self, option: u16) {
        if self.request_options.is_none() {
            self.request_options = Some(Vec::new());
        }
        self.request_options.as_mut().unwrap().push(option).ok();
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{repr}"),
            Err(err) => {
                write!(f, "DHCPv4 ({err})")
            }
        }
    }
}

impl<'a> fmt::Display for Repr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DHCPv6 msg-type={} trans-id={}",
            self.message_type,
            self.transaction_id)?;

        if let Some(server_id) = self.server_id.as_ref() {
            write!(f, " server-id={:X?}", server_id)?;
        }
        if let Some(client_id) = self.client_id.as_ref() {
            write!(f, " client-id={:X?}", client_id)?;
        }
        if let Some(elapsed_time) = self.elapsed_time.as_ref() {
            write!(f, " elapsed-time={}/100s", elapsed_time)?;
        }
        if let Some(request_options) = self.request_options.as_ref() {
            write!(f, " ops=")?;
            for opt in request_options.iter() {
                write!(f, "{opt},")?;
            }
        }
        if let Some(ia_na) = self.ia_na.as_ref() {
            write!(f, " {ia_na}")?;
        }
        if let Some(ia_ta) = self.ia_ta.as_ref() {
            write!(f, " {ia_ta}")?;
        }
        if let Some(dns_servers) = self.dns_servers.as_ref() {
            write!(f, " dns-servers {dns_servers}")?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReprIaNa<'a> {
    /// The unique identifier for this IA_NA
    pub iaid: u32,
    /// Time interval
    pub t1: u32,
    /// Time interval
    pub t2: u32,
    /// Addresses attached to this option
    pub addresses: Vec<ReprIaAddr<'a>, MAX_IA_ADDRESSES>,
    /// Represents a status code applied to this IA
    pub status_code: Option<ReprStatusCode<'a>>,
    /// Additional options
    pub additional_options: &'a [Dhcpv6Option<'a>],
}

impl<'a> ReprIaNa<'a> {
    pub fn data_len(&self) -> usize {
        let mut len = 0;
        len += 4; // IAID
        len += 4; // T1
        len += 4; // T2
        for addr in self.addresses.iter() {
            len += 4 + addr.data_len();
        }
        if let Some(status_code) = self.status_code.as_ref() {
            len += 4 + status_code.data_len()
        }
        for opt in self.additional_options {
            len += 4 + opt.data.len()
        }
        len
    }

    pub fn parse(mut data: &'a [u8]) -> Result<Self>
    {
        let iaid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        data = &data[4..];
        let t1 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        data = &data[4..];
        let t2 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        data = &data[4..];

        let mut addresses = Vec::new();
        let mut status_code = None;
        for option in parse_options(data) {
            let data = option.data;
            match (option.kind, data.len()) {
                (field::OPT_IA_PD, _) => {
                    addresses.push(ReprIaAddr::parse(data)?).ok();
                }
                (field::OPT_STATUS_CODE, _) => {
                    status_code = Some(ReprStatusCode::parse(data)?);
                }
                _ => {}
            }
        }

        Ok(Self {
            iaid,
            t1,
            t2,
            addresses,
            status_code,
            additional_options: &[],
        })
    }

    pub fn emit(&self, dhcp_options: &mut Dhcpv6OptionWriter<'a>) -> Result<()>
    {
        // OPT TYPE
        NetworkEndian::write_u16(&mut dhcp_options.buffer[0..2], field::OPT_IA_NA);
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(2).1;

        // OPT LEN
        NetworkEndian::write_u16(&mut dhcp_options.buffer[0..2], self.data_len() as u16);
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(2).1;

        // IAID
        dhcp_options.buffer[0..4].copy_from_slice(&self.iaid.to_be_bytes());
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(4).1;

        // T1
        dhcp_options.buffer[0..4].copy_from_slice(&self.t1.to_be_bytes());
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(4).1;

        // T2
        dhcp_options.buffer[0..4].copy_from_slice(&self.t2.to_be_bytes());
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(4).1;

        // Addresses
        for addr in self.addresses.iter() {
            addr.emit(dhcp_options)?;
        }

        // Status code
        if let Some(status_code) = self.status_code.as_ref() {
            status_code.emit(dhcp_options)?;
        }
        
        for opt in self.additional_options {
            dhcp_options.emit(*opt)?;
        }

        Ok(())
    }
}

impl<'a> fmt::Display for ReprIaNa<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ia-na iaid={} t1={} t2={}",
            self.iaid,
            self.t1,
            self.t2)?;
        for addr in self.addresses.iter() {
            write!(f, " addr={}", addr)?;
        }
        if let Some(s) = self.status_code.as_ref() {
            write!(f, " status={}(msg='{}')", s.status_code, s.status_message)?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReprIaTa<'a> {
    /// The unique identifier for this IA_TA
    pub iaid: u32,
    /// Addresses attached to this option
    pub addresses: Vec<ReprIaAddr<'a>, MAX_IA_ADDRESSES>,
    /// Represents a status code applied to this IA
    pub status_code: Option<ReprStatusCode<'a>>,
    /// Additional options
    pub additional_options: &'a [Dhcpv6Option<'a>],
}

impl<'a> ReprIaTa<'a> {
    pub fn data_len(&self) -> usize {
        let mut len = 0;
        len += 4; // IAID
        for addr in self.addresses.iter() {
            len += 4 + addr.data_len();
        }
        if let Some(status_code) = self.status_code.as_ref() {
            len += 4 + status_code.data_len()
        }
        for opt in self.additional_options {
            len += 4 + opt.data.len()
        }
        len
    }

    pub fn parse(mut data: &'a [u8]) -> Result<Self>
    {
        let iaid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        data = &data[4..];
        
        let mut addresses = Vec::new();
        let mut status_code = None;
        for option in parse_options(data) {
            let data = option.data;
            match (option.kind, data.len()) {
                (field::OPT_IA_PD, _) => {
                    addresses.push(ReprIaAddr::parse(data)?).ok();
                }
                (field::OPT_STATUS_CODE, _) => {
                    status_code = Some(ReprStatusCode::parse(data)?);
                }
                _ => {}
            }
        }

        Ok(Self {
            iaid,
            addresses,
            status_code,
            additional_options: &[],
        })
    }

    pub fn emit(&self, dhcp_options: &mut Dhcpv6OptionWriter<'a>) -> Result<()>
    {
        // OPT TYPE
        NetworkEndian::write_u16(&mut dhcp_options.buffer[0..2], field::OPT_IA_TA);
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(2).1;

        // OPT LEN
        NetworkEndian::write_u16(&mut dhcp_options.buffer[0..2], self.data_len() as u16);
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(2).1;

        // IAID
        dhcp_options.buffer[0..4].copy_from_slice(&self.iaid.to_be_bytes());
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(4).1;

        // Addresses
        for addr in self.addresses.iter() {
            addr.emit(dhcp_options)?;
        }

        // Status code
        if let Some(status_code) = self.status_code.as_ref() {
            status_code.emit(dhcp_options)?;
        }
        
        for opt in self.additional_options {
            dhcp_options.emit(*opt)?;
        }

        Ok(())
    }
}

impl<'a> fmt::Display for ReprIaTa<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ia-ta iaid={}",
            self.iaid)?;        
        for addr in self.addresses.iter() {
            write!(f, " addr={}", addr)?;
        }
        if let Some(s) = self.status_code.as_ref() {
            write!(f, " status={}(msg='{}')", s.status_code, s.status_message)?;
        }
        Ok(())
    }
}

//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |          OPTION_IAADDR        |          option-len           |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                                                               |
//    |                         IPv6-address                          |
//    |                                                               |
//    |                                                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      preferred-lifetime                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                        valid-lifetime                         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    .                                                               .
//    .                        IAaddr-options                         .
//    .                                                               .
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReprIaAddr<'a> {
    /// The address thats represented here
    pub addr: super::ipv6::Address,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    /// Additional options
    pub additional_options: &'a [Dhcpv6Option<'a>],
}

impl<'a> ReprIaAddr<'a> {
    pub fn data_len(&self) -> usize {
        let mut len = 0;
        len += 16; // addr
        len += 4; // preferred_lifetime
        len += 4; // valid_lifetime
        for opt in self.additional_options {
            len += 4 + opt.data.len()
        }
        len
    }

    pub fn parse(mut data: &'a [u8]) -> Result<Self>
    {
        let addr = super::ipv6::Address::from_bytes(&data[0..16]);
        data = &data[16..];
        let preferred_lifetime = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        data = &data[4..];
        let valid_lifetime = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        data = &data[4..];
        
        for option in parse_options(data) {
            let data = option.data;
            match (option.kind, data.len()) {
                _ => {}
            }
        }

        Ok(Self {
            addr,
            preferred_lifetime,
            valid_lifetime,
            additional_options: &[],
        })
    }

    pub fn emit(&self, dhcp_options: &mut Dhcpv6OptionWriter<'a>) -> Result<()>
    {
        // OPT TYPE
        NetworkEndian::write_u16(&mut dhcp_options.buffer[0..2], field::OPT_IA_PD);
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(2).1;

        // OPT LEN
        NetworkEndian::write_u16(&mut dhcp_options.buffer[0..2], self.data_len() as u16);
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(2).1;

        // Address
        dhcp_options.buffer[0..16].copy_from_slice(&self.addr.0);
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(16).1;

        // preferred_lifetime
        dhcp_options.buffer[0..4].copy_from_slice(&self.preferred_lifetime.to_be_bytes());
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(4).1;

        // valid_lifetime
        dhcp_options.buffer[0..4].copy_from_slice(&self.valid_lifetime.to_be_bytes());
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(4).1;
        
        for opt in self.additional_options {
            dhcp_options.emit(*opt)?;
        }

        Ok(())
    }
}

impl<'a> fmt::Display for ReprIaAddr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}(preferred-lifetime={} valid-lifetime={})",
            self.addr,
            self.preferred_lifetime,
            self.valid_lifetime)?;
        Ok(())
    }
}

enum_with_unknown! {
    pub enum StatusCode(u16) {
        Success = 0,
        UnspecFail = 1,
        NoAddrsAvail = 2,
        NoBinding = 3,
        NotOnLink = 4,
        UseMulticast = 5,
        NoPrefixAvail = 6
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Success => write!(f, "success"),
            Self::UnspecFail => write!(f, "unspec-fail"),
            Self::NoAddrsAvail => write!(f, "no-addrs-avail"),
            Self::NoBinding => write!(f, "no-binding"),
            Self::NotOnLink => write!(f, "not-on-link"),
            Self::UseMulticast => write!(f, "use-multicast"),
            Self::NoPrefixAvail => write!(f, "no-prefix-avail"),
            Self::Unknown(a) => write!(f, "unknown({a})"),
        }
    }
}

//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |       OPTION_STATUS_CODE      |         option-len            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |          status-code          |                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
//    .                                                               .
//    .                        status-message                         .
//    .                                                               .
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReprStatusCode<'a> {
    pub status_code: StatusCode,
    pub status_message: Cow<'a, str>,
}

impl<'a> ReprStatusCode<'a> {
    pub fn data_len(&self) -> usize {
        let mut len = 0;
        len += 2;   // status-code
        len += self.status_message.as_bytes().len();
        len
    }

    pub fn parse(data: &'a [u8]) -> Result<Self>
    {
        if data.len() < 2 {
            return Err(Error);
        }
        let status_code = u16::from_be_bytes([data[0], data[1]]);

        Ok(Self {
            status_code: StatusCode::from(status_code),
            status_message: String::from_utf8_lossy(&data[2..])
        })
    }

    pub fn emit(&self, dhcp_options: &mut Dhcpv6OptionWriter<'a>) -> Result<()>
    {
        // OPT TYPE
        NetworkEndian::write_u16(&mut dhcp_options.buffer[0..2], field::OPT_STATUS_CODE);
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(2).1;

        // OPT LEN
        NetworkEndian::write_u16(&mut dhcp_options.buffer[0..2], self.data_len() as u16);
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(2).1;

        // Status code
        let status_code: u16 = self.status_code.into();
        dhcp_options.buffer[0..2].copy_from_slice(&status_code.to_be_bytes());
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(2).1;

        // Status message
        let len = self.status_message.as_bytes().len();
        dhcp_options.buffer[0..len].copy_from_slice(self.status_message.as_bytes());
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(len).1;

        Ok(())
    }
}

impl<'a> fmt::Display for ReprStatusCode<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}(msg='{}')",
            self.status_code,
            self.status_message,)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReprDnsServers {
    /// IPv6 addresses of DNS servers
    pub addresses: Vec<super::ipv6::Address, MAX_DNS_ADDRESSES>,
}

impl ReprDnsServers {
    pub fn data_len(&self) -> usize {
        let mut len = 0;
        for _ in self.addresses.iter() {
            len += 16;
        }
        len
    }

    pub fn parse(mut data: &[u8]) -> Result<Self>
    {
        let mut addresses = Vec::new();
        while data.len() >= 16 {
            addresses.push(super::ipv6::Address::from_bytes(&data[0..16])).ok();
            data = &data[16..];
        }

        Ok(Self {
            addresses,
        })
    }

    pub fn emit<'a>(&self, dhcp_options: &mut Dhcpv6OptionWriter<'a>) -> Result<()>
    {
        // OPT TYPE
        NetworkEndian::write_u16(&mut dhcp_options.buffer[0..2], field::OPT_DNS_SERVERS);
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(2).1;

        // OPT LEN
        NetworkEndian::write_u16(&mut dhcp_options.buffer[0..2], self.data_len() as u16);
        dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(2).1;

        for addr in self.addresses.iter() {
            dhcp_options.buffer[0..16].copy_from_slice(&addr.0);
            dhcp_options.buffer = core::mem::take(&mut dhcp_options.buffer).split_at_mut(16).1;
        }

        Ok(())
    }
}

impl<'a> fmt::Display for ReprDnsServers {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "dns-server")?;
        for addr in self.addresses.iter() {
            write!(f, " addr={}", addr)?;
        }
        Ok(())
    }
}

use crate::wire::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        let packet = match Packet::new_checked(buffer) {
            Err(err) => return write!(f, "{indent}({err})"),
            Ok(packet) => packet,
        };
        write!(f, "{indent}{packet}")
    }
}