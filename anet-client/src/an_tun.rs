use bytes::BytesMut;
use futures::StreamExt;
use packet::{Error, ip::Packet};
use tokio_util::{
    codec::{Decoder, FramedRead},
    sync::CancellationToken,
};
use tun::BoxError;

pub struct IPPacketCodec;

impl Decoder for IPPacketCodec {
    type Item = Packet<BytesMut>;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let buf = buf.split_to(buf.len());
        Ok(match Packet::no_payload(buf) {
            Ok(pkt) => Some(pkt),
            Err(err) => {
                println!("error {err:?}");
                None
            }
        })
    }
}

pub async fn main_entry(token: CancellationToken) -> Result<(), BoxError> {
    let mut config = tun::Configuration::default();

    config
        .address((10, 0, 0, 9))
        .netmask((255, 255, 255, 0))
        .destination((10, 0, 0, 1))
        .tun_name("anet-client")
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        #[allow(deprecated)]
        config.packet_information(true);
        config.ensure_root_privileges(true);
    });

    #[cfg(target_os = "windows")]
    config.platform_config(|config| {
        config.device_guid(9099482345783245345345_u128);
    });

    let dev = tun::create_as_async(&config)?;

    let mut stream = FramedRead::new(dev, IPPacketCodec);

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                println!("Quit...");
                break;
            }
            Some(packet) = stream.next() => {
                match packet {
                    Ok(pkt) => println!("pkt: {pkt:#?}"),
                    Err(err) => panic!("Error: {err:?}"),
                }
            }
        };
    }
    Ok(())
}