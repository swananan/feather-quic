use std::borrow::Cow;

pub const DEFAULT_INITIAL_PACKET_SIZE: u16 = 1200;
const DEFAULT_MAX_IDLE_TIMEOUT: u64 = 0;
const DEFAULT_MAX_UDP_PAYLOAD_SIZE: u32 = 65527;
const DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 1 << 17;
const DEFAULT_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 1 << 16;
const DEFAULT_MAX_STREAM_DATA_UNI: u64 = 1 << 16;
const DEFAULT_MAX_STREAMS_BIDI: u64 = 100;
const DEFAULT_MAX_STREAMS_UNI: u64 = 100;
const DEFAULT_ACK_DELAY_EXPONENT: u8 = 3;
const DEFAULT_MAX_ACK_DELAY: u16 = 25;
const DEFAULT_DISABLE_ACTIVE_MIGRATION: bool = false;
const DEFAULT_ACTIVE_CONNECTION_ID_LIMIT: u8 = 7;

#[derive(Clone, Default)]
pub struct QuicConfig {
    idle_timeout: Option<u64>,
    first_initial_packet_size: Option<u16>,
    pub(crate) org_dcid: Option<Vec<u8>>,
    pub(crate) scid: Option<Vec<u8>>,

    key_log_file: Option<String>,
    server_name: String,
    alpn: String,
    trigger_key_update: Option<u64>,

    initial_max_data: Option<u64>,
    initial_max_stream_data_bidi_local: Option<u64>,
    initial_max_stream_data_bidi_remote: Option<u64>,
    initial_max_stream_data_uni: Option<u64>,
    initial_max_streams_bidi: Option<u64>,
    initial_max_streams_uni: Option<u64>,
    ack_delay_exponent: Option<u8>,
    max_ack_delay: Option<u16>,
    disable_active_migration: Option<bool>,
    active_connection_id_limit: Option<u8>,
    max_udp_payload_size: Option<u32>,
}

impl QuicConfig {
    pub fn set_first_initial_packet_size(&mut self, first_initial_packet_size: u16) {
        self.first_initial_packet_size = Some(first_initial_packet_size);
    }

    pub(crate) fn get_first_initial_packet_size(&self) -> u16 {
        self.first_initial_packet_size
            .unwrap_or(DEFAULT_INITIAL_PACKET_SIZE)
    }

    pub fn set_idle_timeout(&mut self, idle_timeout: u64) {
        self.idle_timeout = Some(idle_timeout);
    }

    pub(crate) fn get_idle_timeout(&self) -> u64 {
        self.idle_timeout.unwrap_or(DEFAULT_MAX_IDLE_TIMEOUT)
    }

    pub fn set_original_dcid(&mut self, original_dcid: &[u8]) {
        self.org_dcid = Some(original_dcid.to_owned());
    }

    pub fn set_scid(&mut self, scid: &[u8]) {
        self.scid = Some(scid.to_owned());
    }

    pub fn set_initial_max_data(&mut self, initial_max_data: u64) {
        self.initial_max_data = Some(initial_max_data);
    }

    pub(crate) fn get_initial_max_data(&self) -> u64 {
        self.initial_max_data.unwrap_or_else(|| {
            self.get_initial_max_streams_bidi()
                * (self.get_initial_max_stream_data_bidi_local()
                    + self.get_initial_max_stream_data_bidi_remote())
                + self.get_initial_max_streams_uni() * self.get_initial_max_stream_data_uni()
        })
    }

    pub(crate) fn get_initial_max_stream_data_bidi_local(&self) -> u64 {
        self.initial_max_stream_data_bidi_local
            .unwrap_or(DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL)
    }

    pub(crate) fn get_initial_max_stream_data_bidi_remote(&self) -> u64 {
        self.initial_max_stream_data_bidi_remote
            .unwrap_or(DEFAULT_MAX_STREAM_DATA_BIDI_REMOTE)
    }

    pub(crate) fn get_initial_max_stream_data_uni(&self) -> u64 {
        self.initial_max_stream_data_uni
            .unwrap_or(DEFAULT_MAX_STREAM_DATA_UNI)
    }

    pub(crate) fn get_initial_max_streams_uni(&self) -> u64 {
        self.initial_max_streams_uni
            .unwrap_or(DEFAULT_MAX_STREAMS_UNI)
    }

    pub(crate) fn get_initial_max_streams_bidi(&self) -> u64 {
        self.initial_max_streams_bidi
            .unwrap_or(DEFAULT_MAX_STREAMS_BIDI)
    }

    pub(crate) fn get_ack_delay_exponent(&self) -> u8 {
        self.ack_delay_exponent
            .unwrap_or(DEFAULT_ACK_DELAY_EXPONENT)
    }

    pub(crate) fn get_max_ack_delay(&self) -> u16 {
        self.max_ack_delay.unwrap_or(DEFAULT_MAX_ACK_DELAY)
    }

    pub(crate) fn get_disable_active_migration(&self) -> bool {
        self.disable_active_migration
            .unwrap_or(DEFAULT_DISABLE_ACTIVE_MIGRATION)
    }

    pub(crate) fn get_active_connection_id_limit(&self) -> u8 {
        self.active_connection_id_limit
            .unwrap_or(DEFAULT_ACTIVE_CONNECTION_ID_LIMIT)
    }

    pub(crate) fn get_max_udp_payload_size(&self) -> u32 {
        self.max_udp_payload_size
            .unwrap_or(DEFAULT_MAX_UDP_PAYLOAD_SIZE)
    }

    pub fn set_server_name<'a, S>(&mut self, server_name: S)
    where
        S: Into<Cow<'a, str>>,
    {
        self.server_name = server_name.into().into_owned();
    }

    pub(crate) fn get_server_name(&self) -> String {
        self.server_name.clone()
    }

    pub fn set_alpn<'a, S>(&mut self, alpn: S)
    where
        S: Into<Cow<'a, str>>,
    {
        self.alpn = alpn.into().into_owned();
    }

    pub(crate) fn get_alpn(&self) -> String {
        self.alpn.clone()
    }

    pub fn set_key_log_file(&mut self, log_file: String) {
        self.key_log_file = Some(log_file);
    }

    pub(crate) fn get_key_log_file(&self) -> Option<&String> {
        self.key_log_file.as_ref()
    }

    pub fn set_initial_max_stream_data_bidi_local(&mut self, value: u64) {
        self.initial_max_stream_data_bidi_local = Some(value);
    }

    pub fn set_initial_max_stream_data_bidi_remote(&mut self, value: u64) {
        self.initial_max_stream_data_bidi_remote = Some(value);
    }

    pub fn set_initial_max_stream_data_uni(&mut self, value: u64) {
        self.initial_max_stream_data_uni = Some(value);
    }

    pub fn set_initial_max_streams_bidi(&mut self, value: u64) {
        self.initial_max_streams_bidi = Some(value);
    }

    pub fn set_initial_max_streams_uni(&mut self, value: u64) {
        self.initial_max_streams_uni = Some(value);
    }

    pub fn set_ack_delay_exponent(&mut self, value: u8) {
        self.ack_delay_exponent = Some(value);
    }

    pub fn set_max_ack_delay(&mut self, value: u16) {
        self.max_ack_delay = Some(value);
    }

    pub fn set_disable_active_migration(&mut self, value: bool) {
        self.disable_active_migration = Some(value);
    }

    pub fn set_active_connection_id_limit(&mut self, value: u8) {
        self.active_connection_id_limit = Some(value);
    }

    pub fn set_max_udp_payload_size(&mut self, value: u32) {
        self.max_udp_payload_size = Some(value);
    }

    pub fn set_trigger_key_update(&mut self, trigger_key_update: u64) {
        self.trigger_key_update = Some(trigger_key_update);
    }

    pub(crate) fn get_trigger_key_update(&self) -> Option<u64> {
        self.trigger_key_update
    }

    pub(crate) fn clear_trigger_key_update(&mut self) {
        self.trigger_key_update = None
    }
}
