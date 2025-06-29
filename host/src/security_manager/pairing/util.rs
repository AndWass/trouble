use crate::pdu::Pdu;
use crate::security_manager::crypto::{Check, Nonce, PublicKey};
use crate::security_manager::types::Command;
use crate::security_manager::{Reason, TxPacket};
use crate::{Error, PacketPool};
pub fn prepare_packet<P: PacketPool>(command: Command) -> Result<TxPacket<P>, Error> {
    let packet = P::allocate().ok_or(Error::OutOfMemory)?;
    TxPacket::new(packet, command)
}

pub fn make_pairing_random<P: PacketPool>(nonce: &Nonce) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet::<P>(Command::PairingRandom)?;
    let response = packet.payload_mut();
    response.copy_from_slice(&nonce.0.to_le_bytes());
    Ok(packet)
}

pub fn make_public_key_packet<P: PacketPool>(public_key: &PublicKey) -> Result<TxPacket<P>, Error> {
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(public_key.x.as_be_bytes());
    y.copy_from_slice(public_key.y.as_be_bytes());
    x.reverse();
    y.reverse();
    let mut packet = prepare_packet(Command::PairingPublicKey)?;

    let response = packet.payload_mut();

    response[..x.len()].copy_from_slice(&x);
    response[x.len()..y.len() + x.len()].copy_from_slice(&y);
    Ok(packet)
}

pub fn make_dhkey_check_packet<P: PacketPool>(check: &Check) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet(Command::PairingDhKeyCheck)?;
    let response = packet.payload_mut();
    let bytes = check.0.to_le_bytes();
    response[..bytes.len()].copy_from_slice(&bytes);
    Ok(packet)
}

#[derive(Debug, Clone)]
pub struct CommandAndPayload<'a> {
    pub command: Command,
    pub payload: &'a [u8],
}

impl<'a> CommandAndPayload<'a> {
    pub fn try_parse<P: PacketPool>(pdu: Pdu<P::Packet>, buffer: &'a mut [u8]) -> Result<Self, Error> {
        let size = {
            let size = pdu.len().min(buffer.len());
            buffer[..size].copy_from_slice(&pdu.as_ref()[..size]);
            size
        };
        if size < 2 {
            error!("[security manager] Payload size too small {}", size);
            return Err(Error::Security(Reason::InvalidParameters));
        }
        let payload = &buffer[1..size];
        let command = buffer[0];

        let command = match Command::try_from(command) {
            Ok(command) => {
                if usize::from(command.payload_size()) != payload.len() {
                    error!("[security manager] Payload size mismatch for command {}", command);
                    return Err(Error::Security(Reason::InvalidParameters));
                }
                command
            }
            Err(_) => return Err(Error::Security(Reason::CommandNotSupported)),
        };

        Ok(Self { command, payload })
    }
}