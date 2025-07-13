use bt_hci::param::ConnHandle;
use rand_core::{CryptoRng, RngCore};
use crate::{Address, Error, LongTermKey, PacketPool};
use crate::connection::{ConnectionEvent, SecurityLevel};
use crate::host::EventHandler;
use crate::security_manager::{TxPacket};
use crate::security_manager::types::Command;

pub mod peripheral;
pub mod central;
// pub mod central;
mod util;

pub trait PairingOps<P: PacketPool> {
    fn try_send_packet(&mut self, packet: TxPacket<P>) -> Result<(), Error>;
    fn try_enable_encryption(&mut self, ltk: &LongTermKey) -> Result<(), Error>;
    fn connection_handle(&mut self) -> ConnHandle;

    fn try_send_connection_event(&mut self, event: ConnectionEvent) -> Result<(), Error> {
        trace!("Connection event: {:?}", event);
        Ok(())
    }
}

pub enum Pairing {
    Central(central::Pairing),
    Peripheral(peripheral::Pairing),
}

impl Pairing {
    pub(crate) fn is_central(&self) -> bool {
        matches!(self, Pairing::Central(_))
    }
    pub(crate) fn handle_l2cap_command<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(&self, command: Command, payload: &[u8], ops: &mut OPS, rng: &mut RNG, event_handler: &dyn EventHandler) -> Result<(), Error> {
        match self {
            Pairing::Central(central) => central.handle_l2cap_command(command, payload, ops, rng, event_handler),
            Pairing::Peripheral(peripheral) => peripheral.handle_l2cap_command(command, payload, ops, rng, event_handler),
        }
    }

    pub(crate) fn handle_event<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(&self, event: Event, ops: &mut OPS, rng: &mut RNG) -> Result<(), Error> {
        match self {
            Pairing::Central(central) => central.handle_event(event, ops, rng),
            Pairing::Peripheral(peripheral) => peripheral.handle_event(event, ops, rng),
        }
    }

    pub(crate) fn security_level(&self) -> SecurityLevel {
        match self {
            Pairing::Central(c) => c.security_level(),
            Pairing::Peripheral(p) => p.security_level(),
        }
    }
    pub(crate) fn new_central(local_address: Address, peer_address: Address) -> Pairing {
        Pairing::Central(central::Pairing::new_idle(local_address, peer_address))
    }

    pub(crate) fn initiate_central<P: PacketPool, OPS: PairingOps<P>>(local_address: Address, peer_address: Address,
                                                                      ops: &mut OPS) -> Result<Self, Error> {
        Ok(Pairing::Central(central::Pairing::initiate(local_address, peer_address, ops)?))
    }

    pub(crate) fn new_peripheral(local_address: Address, peer_address: Address) -> Pairing {
        Pairing::Peripheral(peripheral::Pairing::new(local_address, peer_address))
    }

    pub(crate) fn peer_address(&self) -> Address {
        match self {
            Pairing::Central(central) => central.peer_address(),
            Pairing::Peripheral(per) => per.peer_address(),
        }
    }
}

pub enum Event {
    LinkEncrypted,
    PassKeyConfirm,
    PassKeyCancel,
    PassKeyInput(u32),
}
