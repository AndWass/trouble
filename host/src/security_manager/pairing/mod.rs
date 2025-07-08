use bt_hci::param::ConnHandle;
use crate::{Error, LongTermKey, PacketPool};
use crate::security_manager::{ConfirmValue, TxPacket};

pub mod peripheral;
// pub mod central;
mod util;

pub trait PairingOps<P: PacketPool> {
    fn try_send_packet(&mut self, packet: TxPacket<P>) -> Result<(), Error>;
    fn try_enable_encryption(&mut self, ltk: &LongTermKey) -> Result<(), Error>;
    fn connection_handle(&mut self) -> ConnHandle;
}

pub struct PairingOpsFns<SP, EE> {
    send_packet: SP,
    enable_encryption: EE,
    connection_handle: ConnHandle,
}

pub fn pairings_ops_from_fn<SP, EE>(handle: ConnHandle, send_packet: SP, enable_encryption: EE) -> PairingOpsFns<SP, EE>
{
    PairingOpsFns {
        connection_handle: handle,
        send_packet,
        enable_encryption,
    }
}

impl<P, SP, SE> PairingOps<P> for PairingOpsFns<SP, SE>
where
    P: PacketPool,
    SP: FnMut(TxPacket<P>) -> Result<(), Error>,
    SE: FnMut(&LongTermKey) -> Result<(), Error>
{
    fn try_send_packet(&mut self, packet: TxPacket<P>) -> Result<(), Error> {
        (self.send_packet)(packet)
    }

    fn try_enable_encryption(&mut self, ltk: &LongTermKey) -> Result<(), Error> {
        (self.enable_encryption)(ltk)
    }

    fn connection_handle(&mut self) -> ConnHandle {
        self.connection_handle
    }
}

pub enum Event {
    LinkEncrypted,
    NumericComparisonConfirm(ConfirmValue),
}
