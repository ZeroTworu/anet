use crate::consts::MAX_PACKET_SIZE;
use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Версия протокола RFB (3.8) для маскировки под стандартный VNC сервер.
pub const RFB_VERSION: &[u8; 12] = b"RFB 003.008\n";
/// Тип аутентификации RFB: 1 = None (без пароля).
pub const SECURITY_TYPE_NONE: u8 = 1;
/// Тип сообщения RFB от клиента: ClientCutText (буфер обмена / туннель данных).
pub const CLIENT_CUT_TEXT: u8 = 6;
/// Тип сообщения RFB от сервера: ServerCutText (буфер обмена / туннель данных).
pub const SERVER_CUT_TEXT: u8 = 3;
/// Тип сообщения RFB от сервера: FramebufferUpdate (обновление области экрана для маскировки Data Plane).
pub const FRAMEBUFFER_UPDATE: u8 = 0;

/// Поддерживаемые сервером типы аутентификации: 1 тип, SecurityType = None.
pub const RFB_SECURITY_TYPES: &[u8] = &[1, SECURITY_TYPE_NONE];
/// Результат безопасности RFB: 4 нулевых байта (SecurityResult OK).
pub const RFB_SECURITY_OK: &[u8] = &[0, 0, 0, 0];
/// Инициализация сервера RFB (ServerInit):
/// Разрешение 1024x768, 32 bpp, глубина 24, little-endian, true-colour, имя десктопа "Xvnc".
pub const RFB_SERVER_INIT: &[u8] = &[
    0x04, 0x00, 0x03, 0x00, // 1024x768
    0x20, 0x18, 0x00, 0x01, // 32 bpp, depth 24, little-endian, true-colour
    0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
    b'X', b'v', b'n', b'c',
];

/// RFB FramebufferUpdate с черным экраном (Raw 1024x768x4 байт) для правдоподобного ответа
/// обычному VNC-клиенту или активному сканеру перед закрытием сеанса.
/// Заголовок FramebufferUpdate: [type=0, pad=0, rect_count=1 (u16)].
pub const RFB_FRAMEBUFFER_UPDATE_HDR: &[u8] = &[
    0x00, 0x00, 0x00, 0x01, // msg_type: 0 (FramebufferUpdate), pad: 0, rect_count: 1
    0x00, 0x00, 0x00, 0x00, // x=0, y=0
    0x04, 0x00, 0x03, 0x00, // width=1024, height=768
    0x00, 0x00, 0x00, 0x00, // encoding: 0 (Raw)
];

const CUT_TEXT_HEADER_LEN: usize = 8;
const FRAMEBUFFER_UPDATE_HEADER_LEN: usize = 16;
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

/// Упаковывает зашифрованный пакет ASTP в кадр RFB `FramebufferUpdate` (`0x00`, Raw encoding = 0,
/// 1 прямоугольник `width = payload.len()`, `height = 1`) для маскировки трафика Server -> Client
/// под передачу пиксельных областей рабочего стола VNC.
pub fn encode_framebuffer_update(payload: &[u8]) -> io::Result<Bytes> {
    if payload.len() > MAX_CUT_TEXT_PAYLOAD || payload.len() > u16::MAX as usize {
        return Err(invalid_data(
            "RFB FramebufferUpdate payload exceeds the transport limit",
        ));
    }

    let mut frame = BytesMut::with_capacity(FRAMEBUFFER_UPDATE_HEADER_LEN + payload.len());
    frame.put_u8(FRAMEBUFFER_UPDATE);
    frame.put_u8(0); // padding
    frame.put_u16(1); // number-of-rectangles = 1
    frame.put_u16(0); // x-position = 0
    frame.put_u16(0); // y-position = 0
    frame.put_u16(payload.len() as u16); // width = payload_len
    frame.put_u16(1); // height = 1
    frame.put_i32(0); // encoding-type = 0 (Raw)
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

pub async fn write_framebuffer_update<W>(writer: &mut W, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&encode_framebuffer_update(payload)?)
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

    // При чтении потока от сервера прозрачно поддерживаем как FramebufferUpdate (0x00),
    // так и классический ServerCutText (0x03) для полной обратной совместимости.
    if expected_type == SERVER_CUT_TEXT && header[0] == FRAMEBUFFER_UPDATE {
        let mut fb_hdr = [0u8; FRAMEBUFFER_UPDATE_HEADER_LEN - 1];
        reader.read_exact(&mut fb_hdr).await?;
        if fb_hdr[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("non-zero RFB FramebufferUpdate padding: {}", fb_hdr[0]),
            ));
        }
        let rect_count = u16::from_be_bytes([fb_hdr[1], fb_hdr[2]]);
        let width = u16::from_be_bytes([fb_hdr[7], fb_hdr[8]]) as usize;
        let height = u16::from_be_bytes([fb_hdr[9], fb_hdr[10]]);
        let encoding = i32::from_be_bytes([fb_hdr[11], fb_hdr[12], fb_hdr[13], fb_hdr[14]]);
        if rect_count != 1 || height != 1 || encoding != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected RFB FramebufferUpdate layout: rects={rect_count}, height={height}, encoding={encoding}"
                ),
            ));
        }
        if width > MAX_CUT_TEXT_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "RFB FramebufferUpdate payload exceeds limit: width={} > MAX={}",
                    width, MAX_CUT_TEXT_PAYLOAD
                ),
            ));
        }
        let mut payload = vec![0; width];
        reader.read_exact(&mut payload).await?;
        return Ok(Some(Bytes::from(payload)));
    }

    reader.read_exact(&mut header[1..]).await?;

    if header[0] != expected_type {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected RFB message type: {} (0x{:02x}), expected {} (0x{:02x})",
                header[0], header[0], expected_type, expected_type
            ),
        ));
    }
    if header[1..4] != [0; 3] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("non-zero RFB CutText padding: {:?}", &header[1..4]),
        ));
    }

    let payload_len =
        u32::from_be_bytes(header[4..8].try_into().expect("fixed-size header")) as usize;
    if payload_len > MAX_CUT_TEXT_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "RFB CutText payload exceeds limit: payload_len={} > MAX={}",
                payload_len, MAX_CUT_TEXT_PAYLOAD
            ),
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
    async fn framebuffer_update_round_trip() {
        let payload = Bytes::from_static(b"encrypted astp downlink frame inside rfb raw rect");
        let frame = encode_framebuffer_update(&payload).unwrap();
        assert_eq!(frame[0], FRAMEBUFFER_UPDATE);
        let mut reader = std::io::Cursor::new(frame);

        let decoded = read_cut_text(&mut reader, SERVER_CUT_TEXT)
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
        assert!(encode_framebuffer_update(&payload).is_err());
    }
}

