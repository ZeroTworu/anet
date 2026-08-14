use crate::consts::MAX_PACKET_SIZE;
use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const RFB_VERSION: &[u8; 12] = b"RFB 003.008\n";
pub const SECURITY_TYPE_NONE: u8 = 1;
pub const CLIENT_CUT_TEXT: u8 = 6;
pub const SERVER_CUT_TEXT: u8 = 3;

const CUT_TEXT_HEADER_LEN: usize = 8;
const MAX_CUT_TEXT_PAYLOAD: usize = MAX_PACKET_SIZE * 2;

pub fn encode_cut_text(message_type: u8, payload: &[u8]) -> io::Result<Bytes> {
    if !matches!(message_type, CLIENT_CUT_TEXT | SERVER_CUT_TEXT) {
        return Err(invalid_data("unsupported RFB CutText message type"));
    }
    if payload.len() > MAX_CUT_TEXT_PAYLOAD {
        return Err(invalid_data(
            "RFB CutText payload exceeds the transport limit",
        ));
    }

    let mut frame = BytesMut::with_capacity(CUT_TEXT_HEADER_LEN + payload.len());
    frame.put_u8(message_type);
    frame.put_slice(&[0; 3]);
    frame.put_u32(payload.len() as u32);
    frame.put_slice(payload);
    Ok(frame.freeze())
}

pub async fn write_cut_text<W>(writer: &mut W, message_type: u8, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&encode_cut_text(message_type, payload)?)
        .await
}

pub async fn read_cut_text<R>(reader: &mut R, expected_type: u8) -> io::Result<Option<Bytes>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; CUT_TEXT_HEADER_LEN];
    match reader.read_exact(&mut header[..1]).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    reader.read_exact(&mut header[1..]).await?;

    if header[0] != expected_type {
        return Err(invalid_data("unexpected RFB message type"));
    }
    if header[1..4] != [0; 3] {
        return Err(invalid_data("non-zero RFB CutText padding"));
    }

    let payload_len =
        u32::from_be_bytes(header[4..8].try_into().expect("fixed-size header")) as usize;
    if payload_len > MAX_CUT_TEXT_PAYLOAD {
        return Err(invalid_data(
            "RFB CutText payload exceeds the transport limit",
        ));
    }

    let mut payload = vec![0; payload_len];
    reader.read_exact(&mut payload).await?;
    Ok(Some(Bytes::from(payload)))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cut_text_round_trip() {
        let payload = Bytes::from_static(b"astp packet");
        let frame = encode_cut_text(CLIENT_CUT_TEXT, &payload).unwrap();
        let mut reader = std::io::Cursor::new(frame);

        let decoded = read_cut_text(&mut reader, CLIENT_CUT_TEXT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decoded, payload);
    }

    #[tokio::test]
    async fn rejects_wrong_message_type() {
        let frame = encode_cut_text(SERVER_CUT_TEXT, b"packet").unwrap();
        let mut reader = std::io::Cursor::new(frame);

        let error = read_cut_text(&mut reader, CLIENT_CUT_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rejects_oversized_payload_before_allocation() {
        let mut frame = vec![CLIENT_CUT_TEXT, 0, 0, 0];
        frame.extend_from_slice(&((MAX_CUT_TEXT_PAYLOAD + 1) as u32).to_be_bytes());
        let mut reader = io::Cursor::new(frame);

        let error = read_cut_text(&mut reader, CLIENT_CUT_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn truncated_header_is_not_treated_as_clean_eof() {
        let mut reader = std::io::Cursor::new(vec![CLIENT_CUT_TEXT, 0, 0]);

        let error = read_cut_text(&mut reader, CLIENT_CUT_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn rejects_oversized_payload_when_encoding() {
        let payload = vec![0; MAX_CUT_TEXT_PAYLOAD + 1];
        assert!(encode_cut_text(CLIENT_CUT_TEXT, &payload).is_err());
    }
}
