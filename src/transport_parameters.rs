use anyhow::{anyhow, Result};
use byteorder::ReadBytesExt;
use byteorder::{BigEndian, WriteBytesExt};
use std::fmt;
use std::io::{Cursor, Read, Seek, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::{error, trace, warn};

use crate::config::QuicConfig;
use crate::utils::{decode_variable_length, encode_variable_length, get_variable_length};

#[allow(dead_code)]
// https://www.rfc-editor.org/rfc/rfc9000.html#section-18
pub(crate) enum TransportParameter {
    // This parameter is the value of the Destination Connection ID field
    // from the first Initial packet sent by the client;
    // see Section 7.3. This transport parameter is only sent by a server.
    OriginalDestinationConnectionId(Vec<u8>),

    // The maximum idle timeout is a value in milliseconds that is encoded as an integer; see (Section 10.1).
    // Idle timeout is disabled when both endpoints omit this transport parameter or specify a value of 0.
    MaxIdleTimeout(u64), // in milliseconds

    // A stateless reset token is used in verifying a stateless reset; see Section 10.3.
    // This parameter is a sequence of 16 bytes. This transport parameter MUST NOT be sent by a client but MAY be sent by a server.
    // A server that does not send this transport parameter cannot use stateless reset (Section 10.3)
    // for the connection ID negotiated during the handshake.
    StatelessResetToken([u8; 16]),

    // The maximum UDP payload size parameter is an integer value that limits the size of UDP payloads
    // that the endpoint is willing to receive.
    // UDP datagrams with payloads larger than this limit are not likely to be processed by the receiver.
    MaxUdpPayloadSize(u32),

    InitialMaxData(u64),

    InitialMaxStreamDataBidiLocal(u64),

    InitialMaxStreamDataBidiRemote(u64),

    InitialMaxStreamDataUni(u64),

    InitialMaxStreamsBidi(u64),

    InitialMaxStreamsUni(u64),

    AckDelayExponent(u8),

    // The maximum acknowledgment delay is an integer value indicating the maximum amount of time in milliseconds by
    // which the endpoint will delay sending acknowledgments. This value SHOULD include the receiver's expected delays in alarms firing.
    // For example, if a receiver sets a timer for 5ms and alarms commonly fire up to 1ms late, then it should send a max_ack_delay of 6ms.
    // If this value is absent, a default of 25 milliseconds is assumed. Values of 1 << 14 or greater are invalid.
    MaxAckDelay(u16),

    DisableActiveMigration(bool),

    PreferredAddress(PreferredAddress),

    ActiveConnectionIdLimit(u8),

    InitialSourceConnectionId(Vec<u8>),

    RetrySourceConnectionId(Vec<u8>),
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct PreferredAddress {
    ipv4_address: Ipv4Addr,
    ipv4_port: u16,
    ipv6_address: Ipv6Addr,
    ipv6_port: u16,
    connection_id_length: u8,
    connection_id: Vec<u8>,
    stateless_reset_token: [u8; 16],
}

impl fmt::Debug for TransportParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportParameter::OriginalDestinationConnectionId(v) => f
                .debug_tuple("OriginalDestinationConnectionId")
                .field(&format_args!("{:02x?}", v))
                .finish(),
            TransportParameter::MaxIdleTimeout(v) => {
                f.debug_tuple("MaxIdleTimeout").field(v).finish()
            }
            TransportParameter::StatelessResetToken(v) => f
                .debug_tuple("StatelessResetToken")
                .field(&format_args!("{:02x?}", v))
                .finish(),
            TransportParameter::MaxUdpPayloadSize(v) => {
                f.debug_tuple("MaxUdpPayloadSize").field(v).finish()
            }
            TransportParameter::InitialMaxData(v) => {
                f.debug_tuple("InitialMaxData").field(v).finish()
            }
            TransportParameter::InitialMaxStreamDataBidiLocal(v) => f
                .debug_tuple("InitialMaxStreamDataBidiLocal")
                .field(v)
                .finish(),
            TransportParameter::InitialMaxStreamDataBidiRemote(v) => f
                .debug_tuple("InitialMaxStreamDataBidiRemote")
                .field(v)
                .finish(),
            TransportParameter::InitialMaxStreamDataUni(v) => {
                f.debug_tuple("InitialMaxStreamDataUni").field(v).finish()
            }
            TransportParameter::InitialMaxStreamsBidi(v) => {
                f.debug_tuple("InitialMaxStreamsBidi").field(v).finish()
            }
            TransportParameter::InitialMaxStreamsUni(v) => {
                f.debug_tuple("InitialMaxStreamsUni").field(v).finish()
            }
            TransportParameter::AckDelayExponent(v) => {
                f.debug_tuple("AckDelayExponent").field(v).finish()
            }
            TransportParameter::MaxAckDelay(v) => f.debug_tuple("MaxAckDelay").field(v).finish(),
            TransportParameter::DisableActiveMigration(b) => {
                f.debug_tuple("DisableActiveMigration").field(b).finish()
            }
            TransportParameter::PreferredAddress(v) => f
                .debug_tuple("PreferredAddress")
                .field(&format_args!("{:02x?}", v))
                .finish(),
            TransportParameter::ActiveConnectionIdLimit(v) => {
                f.debug_tuple("ActiveConnectionIdLimit").field(v).finish()
            }
            TransportParameter::InitialSourceConnectionId(v) => f
                .debug_tuple("InitialSourceConnectionId")
                .field(&format_args!("{:02x?}", v))
                .finish(),
            TransportParameter::RetrySourceConnectionId(v) => f
                .debug_tuple("RetrySourceConnectionId")
                .field(&format_args!("{:02x?}", v))
                .finish(),
        }
    }
}

impl TransportParameter {
    fn type_id(&self) -> u8 {
        match self {
            TransportParameter::OriginalDestinationConnectionId(_) => 0x00,
            TransportParameter::MaxIdleTimeout(_) => 0x01,
            TransportParameter::StatelessResetToken(_) => 0x02,
            TransportParameter::MaxUdpPayloadSize(_) => 0x03,
            TransportParameter::InitialMaxData(_) => 0x04,
            TransportParameter::InitialMaxStreamDataBidiLocal(_) => 0x05,
            TransportParameter::InitialMaxStreamDataBidiRemote(_) => 0x06,
            TransportParameter::InitialMaxStreamDataUni(_) => 0x07,
            TransportParameter::InitialMaxStreamsBidi(_) => 0x08,
            TransportParameter::InitialMaxStreamsUni(_) => 0x09,
            TransportParameter::AckDelayExponent(_) => 0x0A,
            TransportParameter::MaxAckDelay(_) => 0x0B,
            TransportParameter::DisableActiveMigration(_) => 0x0C,
            TransportParameter::PreferredAddress(_) => 0x0D,
            TransportParameter::ActiveConnectionIdLimit(_) => 0x0E,
            TransportParameter::InitialSourceConnectionId(_) => 0x0F,
            TransportParameter::RetrySourceConnectionId(_) => 0x10,
        }
    }

    pub(crate) fn deserialize(cursor: &mut Cursor<&[u8]>) -> Result<Option<TransportParameter>> {
        let type_id = cursor.read_u8()?;
        trace!(
            "Deserializing transport parameter type 0x{:02x} at position {}",
            type_id,
            cursor.position() - 1
        );

        let tp = match type_id {
            0x00 => {
                let id_len = decode_variable_length(cursor)?;
                trace!(
                    "OriginalDestinationConnectionId length {} at position {}",
                    id_len,
                    cursor.position()
                );
                let mut org_dcid = vec![0; id_len as usize];
                cursor.read_exact(&mut org_dcid)?;
                trace!(
                    "Read OriginalDestinationConnectionId: {:02x?} at position {}",
                    org_dcid,
                    cursor.position()
                );
                TransportParameter::OriginalDestinationConnectionId(org_dcid)
            }
            0x01 => {
                let timeout_len = decode_variable_length(cursor)?;
                trace!(
                    "MaxIdleTimeout length {} at position {}",
                    timeout_len,
                    cursor.position()
                );
                let timeout = decode_variable_length(cursor)?;
                trace!(
                    "MaxIdleTimeout value {} at position {}",
                    timeout,
                    cursor.position()
                );
                TransportParameter::MaxIdleTimeout(timeout)
            }
            0x02 => {
                let token_len = decode_variable_length(cursor)?;
                trace!(
                    "StatelessResetToken length {} at position {}",
                    token_len,
                    cursor.position()
                );
                let mut token = vec![0; token_len as usize];
                cursor.read_exact(&mut token)?;
                trace!(
                    "StatelessResetToken value {:02x?} at position {}",
                    token,
                    cursor.position()
                );
                TransportParameter::StatelessResetToken(token.try_into().unwrap())
            }
            0x03 => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "MaxUdpPayloadSize length {} at position {}",
                    len,
                    cursor.position()
                );
                let size = decode_variable_length(cursor)?;
                trace!(
                    "MaxUdpPayloadSize value {} at position {}",
                    size,
                    cursor.position()
                );
                TransportParameter::MaxUdpPayloadSize(size as u32)
            }
            0x04 => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxData length {} at position {}",
                    len,
                    cursor.position()
                );
                let max_data = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxData value {} at position {}",
                    max_data,
                    cursor.position()
                );
                TransportParameter::InitialMaxData(max_data)
            }
            0x05 => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamDataBidiLocal length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamDataBidiLocal value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::InitialMaxStreamDataBidiLocal(value)
            }
            0x06 => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamDataBidiRemote length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamDataBidiRemote value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::InitialMaxStreamDataBidiRemote(value)
            }
            0x07 => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamDataUni length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamDataUni value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::InitialMaxStreamDataUni(value)
            }
            0x08 => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamsBidi length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamsBidi value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::InitialMaxStreamsBidi(value)
            }
            0x09 => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamsUni length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamsUni value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::InitialMaxStreamsUni(value)
            }
            0x0A => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "AckDelayExponent length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                trace!(
                    "AckDelayExponent value {} at position {}",
                    value,
                    cursor.position()
                );
                if value > 20 {
                    return Err(anyhow!(
                        "ack_delay_exponent value {value} is not valid, must below 20"
                    ));
                }
                TransportParameter::AckDelayExponent(value as u8)
            }
            0x0B => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "MaxAckDelay length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                if value >= 1 << 14 {
                    return Err(anyhow!(
                        "max_ack_delay value {value} is not valid, must greater then 213"
                    ));
                }
                trace!(
                    "MaxAckDelay value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::MaxAckDelay(value as u16)
            }
            0x0C => {
                let value = decode_variable_length(cursor)?;
                trace!(
                    "DisableActiveMigration value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::DisableActiveMigration(value == 0)
            }
            0x0D => {
                unimplemented!();
            }
            0x0E => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "ActiveConnectionIdLimit length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                trace!(
                    "ActiveConnectionIdLimit value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::ActiveConnectionIdLimit(value as u8)
            }
            0x0F => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "InitialSourceConnectionId length {} at position {}",
                    len,
                    cursor.position()
                );
                let mut value = vec![0; len as usize];
                cursor.read_exact(&mut value)?;
                trace!(
                    "InitialSourceConnectionId value {:02x?} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::InitialSourceConnectionId(value)
            }
            0x10 => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "RetrySourceConnectionId length {} at position {}",
                    len,
                    cursor.position()
                );
                let mut value = vec![0; len as usize];
                cursor.read_exact(&mut value)?;
                trace!(
                    "RetrySourceConnectionId value {:02x?} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::RetrySourceConnectionId(value)
            }
            _ => {
                // TODO: Could be version_infomation parameter
                // https://www.rfc-editor.org/info/rfc9368
                // or Ack frequency
                // https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency
                error!(
                    "Invalid or unsupported transport parameter type id: 0x{:x}",
                    type_id,
                );

                return Ok(None);
            }
        };

        trace!("Completed deserializing transport parameter {:?}", tp);
        Ok(Some(tp))
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#section-18
    pub(crate) fn serialize<W>(&self, cursor: &mut W) -> Result<()>
    where
        W: Write + Seek + Read,
    {
        // Write the type ID for this transport parameter
        encode_variable_length(cursor, self.type_id() as u64)?;

        match self {
            TransportParameter::OriginalDestinationConnectionId(id) => {
                encode_variable_length(cursor, id.len() as u64)?;
                cursor.write_all(id)?;
            }
            TransportParameter::MaxIdleTimeout(timeout) => {
                encode_variable_length(cursor, get_variable_length(*timeout)? as u64)?;
                encode_variable_length(cursor, *timeout)?;
            }
            TransportParameter::StatelessResetToken(token) => {
                encode_variable_length(cursor, token.len() as u64)?;
                cursor.write_all(token)?;
            }
            TransportParameter::MaxUdpPayloadSize(data) => {
                encode_variable_length(cursor, get_variable_length(*data as u64)? as u64)?;
                encode_variable_length(cursor, *data as u64)?;
            }
            TransportParameter::InitialMaxData(data) => {
                encode_variable_length(cursor, get_variable_length(*data)? as u64)?;
                encode_variable_length(cursor, *data)?;
            }
            TransportParameter::InitialMaxStreamDataBidiLocal(data) => {
                encode_variable_length(cursor, get_variable_length(*data)? as u64)?;
                encode_variable_length(cursor, *data)?;
            }
            TransportParameter::InitialMaxStreamDataBidiRemote(data) => {
                encode_variable_length(cursor, get_variable_length(*data)? as u64)?;
                encode_variable_length(cursor, *data)?;
            }
            TransportParameter::InitialMaxStreamDataUni(data) => {
                encode_variable_length(cursor, get_variable_length(*data)? as u64)?;
                encode_variable_length(cursor, *data)?;
            }
            TransportParameter::InitialMaxStreamsBidi(data) => {
                encode_variable_length(cursor, get_variable_length(*data)? as u64)?;
                encode_variable_length(cursor, *data)?;
            }
            TransportParameter::InitialMaxStreamsUni(data) => {
                encode_variable_length(cursor, get_variable_length(*data)? as u64)?;
                encode_variable_length(cursor, *data)?;
            }
            TransportParameter::AckDelayExponent(data) => {
                encode_variable_length(cursor, get_variable_length(*data as u64)? as u64)?;
                encode_variable_length(cursor, *data as u64)?;
            }
            TransportParameter::MaxAckDelay(data) => {
                encode_variable_length(cursor, get_variable_length(*data as u64)? as u64)?;
                encode_variable_length(cursor, *data as u64)?;
            }
            TransportParameter::DisableActiveMigration(_) => {
                encode_variable_length(cursor, 0)?;
            }
            TransportParameter::PreferredAddress(_) => {
                unimplemented!();
                /* address.serialize(cursor)?; */
            }
            TransportParameter::ActiveConnectionIdLimit(data) => {
                encode_variable_length(cursor, get_variable_length(*data as u64)? as u64)?;
                encode_variable_length(cursor, *data as u64)?;
            }
            TransportParameter::InitialSourceConnectionId(id) => {
                encode_variable_length(cursor, id.len() as u64)?;
                cursor.write_all(id)?;
            }
            TransportParameter::RetrySourceConnectionId(id) => {
                encode_variable_length(cursor, id.len() as u64)?;
                cursor.write_all(id)?;
            }
        }

        Ok(())
    }
}

impl PreferredAddress {
    fn _serialize(&self, cursor: &mut Cursor<&mut [u8]>) -> Result<()> {
        // Preferred Address {
        //   IPv4 Address (32),
        //   IPv4 Port (16),
        //   IPv6 Address (128),
        //   IPv6 Port (16),
        //   Connection ID Length (8),
        //   Connection ID (..),
        //   Stateless Reset Token (128),
        // }
        cursor.write_all(&self.ipv4_address.octets())?;
        cursor.write_u16::<BigEndian>(self.ipv4_port)?;
        cursor.write_all(&self.ipv6_address.octets())?;
        cursor.write_u16::<BigEndian>(self.ipv6_port)?;
        cursor.write_u8(self.connection_id_length)?;
        cursor.write_all(&self.connection_id)?;
        cursor.write_all(&self.stateless_reset_token)?;
        Ok(())
    }
}

pub(crate) fn search_transport_parameters<F>(
    tps: &[TransportParameter],
    condition: F,
) -> Option<&TransportParameter>
where
    F: Fn(&TransportParameter) -> bool,
{
    tps.iter().find(|&item| condition(item))
}

pub(crate) fn parse_server_transport_parameters(
    cursor: &mut Cursor<&[u8]>,
    length: u16,
) -> Result<Vec<TransportParameter>> {
    let mut tp = vec![];
    let tp_start_pos = cursor.position();
    trace!(
        "Start to parse server transport parameter, start pos {}, tp size {}",
        tp_start_pos,
        length
    );

    while cursor.position() - tp_start_pos < length as u64 {
        if let Some(t) = TransportParameter::deserialize(cursor)? {
            tp.push(t);
        } else {
            warn!("We will skip the next QUIC parameters due to the current invalid or unsupported parameter");
            cursor.set_position(length as u64 + tp_start_pos);
            break;
        }
    }

    if cursor.position() != tp_start_pos + (length as u64) {
        return Err(anyhow!(
            "Invalid server transport parameter length {} \
            , tp_start_pos: {}, cursor_pos: {}",
            length,
            tp_start_pos,
            cursor.position()
        ));
    }

    Ok(tp)
}

pub(crate) fn create_client_transport_parameters(
    quic_config: &QuicConfig,
    scid: &[u8],
) -> Vec<TransportParameter> {
    vec![
        TransportParameter::MaxIdleTimeout(quic_config.get_idle_timeout()),
        TransportParameter::InitialMaxData(quic_config.get_initial_max_data()),
        TransportParameter::InitialSourceConnectionId(scid.to_vec()),
        TransportParameter::InitialMaxStreamDataBidiLocal(
            quic_config.get_initial_max_stream_data_bidi_local(),
        ),
        TransportParameter::InitialMaxStreamDataBidiRemote(
            quic_config.get_initial_max_stream_data_bidi_remote(),
        ),
        TransportParameter::InitialMaxStreamDataUni(quic_config.get_initial_max_stream_data_uni()),
        TransportParameter::InitialMaxStreamsBidi(quic_config.get_initial_max_streams_bidi()),
        TransportParameter::InitialMaxStreamsUni(quic_config.get_initial_max_streams_uni()),
        TransportParameter::AckDelayExponent(quic_config.get_ack_delay_exponent()),
        TransportParameter::MaxAckDelay(quic_config.get_max_ack_delay()),
        TransportParameter::DisableActiveMigration(quic_config.get_disable_active_migration()),
        TransportParameter::ActiveConnectionIdLimit(quic_config.get_active_connection_id_limit()),
        TransportParameter::MaxUdpPayloadSize(quic_config.get_max_udp_payload_size()),
    ]
}
