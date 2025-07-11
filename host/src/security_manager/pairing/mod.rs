use bt_hci::param::ConnHandle;
use crate::{Error, LongTermKey, PacketPool};
use crate::security_manager::{PassKey, Reason, TxPacket};

pub mod peripheral;
pub mod central;
// pub mod central;
mod util;

pub trait PairingOps<P: PacketPool> {
    fn try_send_packet(&mut self, packet: TxPacket<P>) -> Result<(), Error>;
    fn try_enable_encryption(&mut self, ltk: &LongTermKey) -> Result<(), Error>;
    fn connection_handle(&mut self) -> ConnHandle;

    fn try_display_pass_key(&mut self, pass_key: PassKey) -> Result<(), Error> {
        info!("Display pass key: {}", pass_key);
        Ok(())
    }

    fn try_confirm_pass_key(&mut self, pass_key: PassKey) -> Result<(), Error> {
        warn!("Unimplemented confirm pass key: {}", pass_key);
        Err(Error::Security(Reason::UnspecifiedReason))
    }
}

pub struct PairingOpsFns<SP, EE> {
    send_packet: SP,
    enable_encryption: EE,
    connection_handle: ConnHandle,
}

pub enum Event {
    LinkEncrypted,
    PassKeyConfirm,
    PassKeyCancel,
}
