use crate::connection::{QuicConnection, QuicLevel};
use tracing::{error, info};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuicConnectionErrorCode {
    ApplicationErrorCode(u64),
    TransportErrorCode((TransportErrorCode, Option<u64>)),
}

impl QuicConnectionErrorCode {
    pub(crate) fn create_application_error_code(error_code: u64) -> Self {
        QuicConnectionErrorCode::ApplicationErrorCode(error_code)
    }

    pub(crate) fn create_transport_error_code(error_code: u64, frame_type: Option<u64>) -> Self {
        QuicConnectionErrorCode::TransportErrorCode((
            TransportErrorCode::from(error_code),
            frame_type,
        ))
    }

    pub(crate) fn get_error_code(&self) -> u64 {
        match self {
            QuicConnectionErrorCode::TransportErrorCode((te, _)) => u64::from(*te),
            QuicConnectionErrorCode::ApplicationErrorCode(e) => *e,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TlsError {
    CloseNotify,
    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    HandshakeFailure,
    BadCertificate,
    UnsupportedCertificate,
    CertificateRevoked,
    CertificateExpired,
    CertificateUnknown,
    IllegalParameter,
    UnknownCa,
    AccessDenied,
    DecodeError,
    DecryptError,
    ProtocolVersion,
    InsufficientSecurity,
    InternalError,
    InappropriateFallback,
    UserCanceled,
    MissingExtension,
    UnsupportedExtension,
    UnrecognizedName,
    BadCertificateStatusResponse,
    UnknownPskIdentity,
    CertificateRequired,
    NoApplicationProtocol,
}

impl TlsError {
    fn to_alert_code(self) -> u8 {
        match self {
            TlsError::CloseNotify => 0,
            TlsError::UnexpectedMessage => 10,
            TlsError::BadRecordMac => 20,
            TlsError::RecordOverflow => 22,
            TlsError::HandshakeFailure => 40,
            TlsError::BadCertificate => 42,
            TlsError::UnsupportedCertificate => 43,
            TlsError::CertificateRevoked => 44,
            TlsError::CertificateExpired => 45,
            TlsError::CertificateUnknown => 46,
            TlsError::IllegalParameter => 47,
            TlsError::UnknownCa => 48,
            TlsError::AccessDenied => 49,
            TlsError::DecodeError => 50,
            TlsError::DecryptError => 51,
            TlsError::ProtocolVersion => 70,
            TlsError::InsufficientSecurity => 71,
            TlsError::InternalError => 80,
            TlsError::InappropriateFallback => 86,
            TlsError::UserCanceled => 90,
            TlsError::MissingExtension => 109,
            TlsError::UnsupportedExtension => 110,
            TlsError::UnrecognizedName => 112,
            TlsError::BadCertificateStatusResponse => 113,
            TlsError::UnknownPskIdentity => 115,
            TlsError::CertificateRequired => 116,
            TlsError::NoApplicationProtocol => 120,
        }
    }

    pub(crate) fn to_quic_error_code(self) -> u64 {
        0x0100 + (self.to_alert_code() as u64)
    }

    pub(crate) fn to_error_message(self) -> String {
        match self {
            TlsError::CloseNotify => "TLS close notify".to_string(),
            TlsError::UnexpectedMessage => "TLS unexpected message".to_string(),
            TlsError::BadRecordMac => "TLS bad record MAC".to_string(),
            TlsError::RecordOverflow => "TLS record overflow".to_string(),
            TlsError::HandshakeFailure => "TLS handshake failure".to_string(),
            TlsError::BadCertificate => "TLS bad certificate".to_string(),
            TlsError::UnsupportedCertificate => "TLS unsupported certificate".to_string(),
            TlsError::CertificateRevoked => "TLS certificate revoked".to_string(),
            TlsError::CertificateExpired => "TLS certificate expired".to_string(),
            TlsError::CertificateUnknown => "TLS certificate unknown".to_string(),
            TlsError::IllegalParameter => "TLS illegal parameter".to_string(),
            TlsError::UnknownCa => "TLS unknown CA".to_string(),
            TlsError::AccessDenied => "TLS access denied".to_string(),
            TlsError::DecodeError => "TLS decode error".to_string(),
            TlsError::DecryptError => "TLS decrypt error".to_string(),
            TlsError::ProtocolVersion => "TLS protocol version".to_string(),
            TlsError::InsufficientSecurity => "TLS insufficient security".to_string(),
            TlsError::InternalError => "TLS internal error".to_string(),
            TlsError::InappropriateFallback => "TLS inappropriate fallback".to_string(),
            TlsError::UserCanceled => "TLS user canceled".to_string(),
            TlsError::MissingExtension => "TLS missing extension".to_string(),
            TlsError::UnsupportedExtension => "TLS unsupported extension".to_string(),
            TlsError::UnrecognizedName => "TLS unrecognized name".to_string(),
            TlsError::BadCertificateStatusResponse => {
                "TLS bad certificate status response".to_string()
            }
            TlsError::UnknownPskIdentity => "TLS unknown PSK identity".to_string(),
            TlsError::CertificateRequired => "TLS certificate required".to_string(),
            TlsError::NoApplicationProtocol => "TLS no application protocol".to_string(),
        }
    }
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportErrorCode {
    NoError = 0x00,
    InternalError = 0x01,
    ConnectionRefused = 0x02,
    FlowControlError = 0x03,
    StreamLimitError = 0x04,
    StreamStateError = 0x05,
    FinalSizeError = 0x06,
    FrameEncodingError = 0x07,
    TransportParameterError = 0x08,
    ConnectionIdLimitError = 0x09,
    ProtocolViolation = 0x0a,
    InvalidToken = 0x0b,
    ApplicationError = 0x0c,
    CryptoBufferExceeded = 0x0d,
    KeyUpdateError = 0x0e,
    AeadLimitReached = 0x0f,
    NoViablePath = 0x10,
    CryptoError(u8),
    Unknown(u16),
}

impl TransportErrorCode {
    pub(crate) fn send_crypto_buffer_exceeded_cc_frame(qconn: &mut QuicConnection) {
        error!("Crypto buffer exceeded, so closed the connection");
        qconn.send_transport_connection_close_frame(
            &[QuicLevel::Initial, QuicLevel::Handshake],
            u64::from(TransportErrorCode::CryptoBufferExceeded),
            Some("Crypto buffer exceeded".to_string()),
            None,
        );
    }

    pub(crate) fn send_crypto_error_cc_frame(
        qconn: &mut QuicConnection,
        tls_error: TlsError,
        levels: Vec<QuicLevel>,
    ) {
        error!("TLS error occurred: {:?}", tls_error);
        qconn.send_transport_connection_close_frame(
            &levels,
            tls_error.to_quic_error_code(),
            Some(tls_error.to_error_message()),
            None,
        );
    }

    pub(crate) fn send_no_error_cc_frame(qconn: &mut QuicConnection, level: QuicLevel) {
        info!("Received connection close frame, so reponse a no-error connection close frame, level: {:?}", level);
        qconn.send_transport_connection_close_frame(
            &[level],
            u64::from(TransportErrorCode::NoError),
            Some(
                "Received connection close frame, so reponse a no-error connection close frame"
                    .to_string(),
            ),
            None,
        );
    }

    pub(crate) fn send_stream_limit_error_cc_frame(qconn: &mut QuicConnection) {
        error!("Detected errors in receiving new stream here, so closed the connection");
        qconn.send_transport_connection_close_frame(
            &[QuicLevel::Application],
            u64::from(TransportErrorCode::StreamLimitError),
            Some("Detected limitation errors in opening the new stream".to_string()),
            None,
        );
    }

    pub(crate) fn send_key_update_error_cc_frame(qconn: &mut QuicConnection) {
        error!("Detected errors in performing key updates here, so closed the connection");
        qconn.send_transport_connection_close_frame(
            &[QuicLevel::Application],
            u64::from(TransportErrorCode::KeyUpdateError),
            Some("Detected errors in performing key updates".to_string()),
            None,
        );
    }

    pub(crate) fn send_frame_encoding_error_cc_frame(
        qconn: &mut QuicConnection,
        is_short_header: bool,
    ) {
        error!(
            "An endpoint received a frame that was badly formatted here, so closed the connection \
            is_short_header {}",
            is_short_header
        );
        qconn.send_transport_connection_close_frame(
            if is_short_header {
                &[QuicLevel::Application]
            } else {
                &[QuicLevel::Handshake, QuicLevel::Initial]
            },
            u64::from(TransportErrorCode::FrameEncodingError),
            Some("An endpoint received a frame that was badly formatted".to_string()),
            None,
        );
    }
}

impl From<TransportErrorCode> for u64 {
    fn from(code: TransportErrorCode) -> Self {
        match code {
            TransportErrorCode::CryptoError(x) => 0x0100 + (x as u64),
            TransportErrorCode::Unknown(x) => x as u64,
            TransportErrorCode::NoError => 0x00,
            TransportErrorCode::InternalError => 0x01,
            TransportErrorCode::ConnectionRefused => 0x02,
            TransportErrorCode::FlowControlError => 0x03,
            TransportErrorCode::StreamLimitError => 0x04,
            TransportErrorCode::StreamStateError => 0x05,
            TransportErrorCode::FinalSizeError => 0x06,
            TransportErrorCode::FrameEncodingError => 0x07,
            TransportErrorCode::TransportParameterError => 0x08,
            TransportErrorCode::ConnectionIdLimitError => 0x09,
            TransportErrorCode::ProtocolViolation => 0x0a,
            TransportErrorCode::InvalidToken => 0x0b,
            TransportErrorCode::ApplicationError => 0x0c,
            TransportErrorCode::CryptoBufferExceeded => 0x0d,
            TransportErrorCode::KeyUpdateError => 0x0e,
            TransportErrorCode::AeadLimitReached => 0x0f,
            TransportErrorCode::NoViablePath => 0x10,
        }
    }
}

impl From<u64> for TransportErrorCode {
    fn from(value: u64) -> Self {
        if (0x0100..=0x01ff).contains(&value) {
            TransportErrorCode::CryptoError((value - 0x0100) as u8)
        } else {
            match value as u16 {
                0x00 => TransportErrorCode::NoError,
                0x01 => TransportErrorCode::InternalError,
                0x02 => TransportErrorCode::ConnectionRefused,
                0x03 => TransportErrorCode::FlowControlError,
                0x04 => TransportErrorCode::StreamLimitError,
                0x05 => TransportErrorCode::StreamStateError,
                0x06 => TransportErrorCode::FinalSizeError,
                0x07 => TransportErrorCode::FrameEncodingError,
                0x08 => TransportErrorCode::TransportParameterError,
                0x09 => TransportErrorCode::ConnectionIdLimitError,
                0x0a => TransportErrorCode::ProtocolViolation,
                0x0b => TransportErrorCode::InvalidToken,
                0x0c => TransportErrorCode::ApplicationError,
                0x0d => TransportErrorCode::CryptoBufferExceeded,
                0x0e => TransportErrorCode::KeyUpdateError,
                0x0f => TransportErrorCode::AeadLimitReached,
                0x10 => TransportErrorCode::NoViablePath,
                x => TransportErrorCode::Unknown(x),
            }
        }
    }
}
