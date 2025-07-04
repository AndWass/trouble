#![warn(missing_docs)]
//! # Bluetooth Security Manager
// ([Vol 3] Part H, Section 3.5.5)

mod constants;
mod crypto;
mod types;
mod pairing;

use core::cell::RefCell;
use core::future::{poll_fn, Future};
use core::ops::DerefMut;

use bt_hci::event::le::LeEvent;
use bt_hci::event::Event;
use bt_hci::param::{ConnHandle, LeConnRole};
pub use crypto::{IdentityResolvingKey, LongTermKey};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, TimeoutError, WithTimeout};
use heapless::Vec;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
pub use types::Reason;
use types::{Command};

use crate::connection_manager::{ConnectionManager, ConnectionStorage};
use crate::pdu::Pdu;
use crate::prelude::Connection;
use crate::types::l2cap::L2CAP_CID_LE_U_SECURITY_MANAGER;
use crate::{Address, Error, Identity, PacketPool};
use crate::security_manager::pairing::pairings_ops_from_fn;
use crate::security_manager::pairing::peripheral::Pairing;

/// Events of interest to the security manager
pub(crate) enum SecurityEventData {
    /// A long term key request has been issued
    SendLongTermKey(ConnHandle),
    /// Enable encryption on channel
    EnableEncryption(ConnHandle, BondInformation),
    /// Pairing timeout
    Timeout,
    /// Oairing timer changed
    TimerChange,
}

/// Bond Information
#[derive(Clone, Debug, PartialEq)]
pub struct BondInformation {
    /// Long Term Key (LTK)
    pub ltk: LongTermKey,
    /// Peer identity
    pub identity: Identity,
    // Connection Signature Resolving Key (CSRK)?
}

impl BondInformation {
    /// Create a BondInformation
    pub fn new(identity: Identity, ltk: LongTermKey) -> Self {
        Self { ltk, identity }
    }
}

impl core::fmt::Display for BondInformation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Identity {:?} LTK {}", self.identity, self.ltk)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for BondInformation {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "Identity {:?} LTK {}", self.identity, self.ltk);
    }
}

/// Security manager data
struct SecurityManagerData<const BOND_COUNT: usize> {
    /// Local device address
    local_address: Option<Address>,
    /// Current bonds with other devices
    bond: Vec<BondInformation, BOND_COUNT>,
    /// Random generator seeded
    random_generator_seeded: bool,
}

impl<const BOND_COUNT: usize> SecurityManagerData<BOND_COUNT> {
    /// Create a new security manager data structure
    pub(crate) fn new() -> Self {
        Self {
            local_address: None,
            bond: Vec::new(),
            random_generator_seeded: false,
        }
    }
}

/// Packet structure for sending security manager protocol (SMP) commands
struct TxPacket<P: PacketPool> {
    /// Underlying packet
    packet: P::Packet,
    /// Command to send
    command: Command,
}

impl<P: PacketPool> TxPacket<P> {
    /// Size of L2CAP header and command
    const HEADER_SIZE: usize = 5;

    /// Get a packet from the pool
    pub fn new(mut packet: P::Packet, command: Command) -> Result<Self, Error> {
        let packet_data = packet.as_mut();
        let smp_size = command.payload_size() + 1;
        packet_data[..2].copy_from_slice(&(smp_size).to_le_bytes());
        packet_data[2..4].copy_from_slice(&L2CAP_CID_LE_U_SECURITY_MANAGER.to_le_bytes());
        packet_data[4] = command.into();
        Ok(Self { packet, command })
    }
    /// Packet command
    pub fn command(&self) -> Command {
        self.command
    }

    /// Packet payload
    pub fn payload(&self) -> &[u8] {
        &self.packet.as_ref()[Self::HEADER_SIZE..Self::HEADER_SIZE + usize::from(self.command.payload_size())]
    }
    /// Package mutable payload
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.packet.as_mut()[Self::HEADER_SIZE..Self::HEADER_SIZE + usize::from(self.command.payload_size())]
    }
    /// Package size
    pub fn total_size(&self) -> usize {
        usize::from(self.command.payload_size()) + Self::HEADER_SIZE
    }
    /// Create a PDU from the packet
    pub fn into_pdu(self) -> Pdu<P::Packet> {
        let len = self.total_size();
        Pdu::new(self.packet, len)
    }
}

/// Pairing methods
#[derive(Debug, Clone, Copy, PartialEq)]
enum PairingMethod {
    /// Uninitialized pairing
    None,
    /// Numeric Comparison
    LeSecureConnectionNumericComparison,
    /// Passkey entry
    LeSecureConnectionPasskey,
    /// Out-of-band
    LeSecureConnectionOob,
}

// TODO: IRK exchange, HCI_LE_­Add_­Device_­To_­Resolving_­List

// LESC LE Security Connections Pairing over L2CAP
// Central               Peripheral
// ------ Phase 1 ------
// Optional Security Request <----
// Pairing Request ---->
// Pairing Response <---
// ------ Phase 2 -------
// Pairing Public Key ---->
// Pairing Public Key <----
// ----- Numeric Comparison -----
// Pairing Confirm <----
// Pairing Random ---->
// Pairing Random <----
// ----- Passkey -----
// Keypress notification <----
// Pairing Confirm ---->
// Pairing Confirm <----
// Pairing Random ---->
// Pairing Random <----
// ----- Out-of-band -----
//  --- OOB Confirm ---
// Pairing Random ---->
// Pairing Random <----
// ------ Phase 3 ------
// Pairing DH key check ---->
// Pairing DH key check <----
// ----- Key Distribution (HCI) -----

/// Security manager that handles SM packet
pub struct SecurityManager<const BOND_COUNT: usize> {
    /// Random generator
    rng: RefCell<ChaCha12Rng>,
    /// Security manager data
    state: RefCell<SecurityManagerData<BOND_COUNT>>,
    /// State of an ongoing pairing as a peripheral
    peripheral_pairing_sm: RefCell<Option<Pairing>>,
    //pairing_state: RefCell<PairingData>,
    /// Received events
    events: Channel<NoopRawMutex, SecurityEventData, 2>,
    result_signal: Signal<NoopRawMutex, Reason>,
    /// Timer
    timer_expires: RefCell<Instant>,
}

enum TimerCommand {
    Stop,
    Start,
}

impl<const BOND_COUNT: usize> SecurityManager<BOND_COUNT> {
    /// Create a new SecurityManager
    pub(crate) fn new() -> Self {
        let random_seed = [0u8; 32];
        Self {
            rng: RefCell::new(ChaCha12Rng::from_seed(random_seed)),
            state: RefCell::new(SecurityManagerData::new()),
            events: Channel::new(),
            peripheral_pairing_sm: RefCell::new(None),
            result_signal: Signal::new(),
            timer_expires: RefCell::new(Instant::now() + Self::TIMEOUT_DISABLE),
        }
    }

    /// Set the current local address
    pub(crate) fn set_random_generator_seed(&self, random_seed: [u8; 32]) {
        self.rng.replace(ChaCha12Rng::from_seed(random_seed));
        self.state.borrow_mut().random_generator_seeded = true;
    }

    /// Set the current local address
    pub(crate) fn set_local_address(&self, address: Address) {
        self.state.borrow_mut().local_address = Some(address);
    }

    /// Get the long term key for peer
    pub(crate) fn get_peer_long_term_key(&self, identity: &Identity) -> Option<LongTermKey> {
        trace!("[security manager] Find long term key for {:?}", identity);
        self.state.borrow().bond.iter().find_map(|bond| {
            if bond.identity.match_identity(identity) {
                Some(bond.ltk)
            } else {
                None
            }
        })
    }

    /// Get the result of the pairing
    pub(crate) async fn get_result(&self) -> Reason {
        self.result_signal.wait().await
    }

    /// Has the random generator been seeded?
    pub(crate) fn get_random_generator_seeded(&self) -> bool {
        self.state.borrow().random_generator_seeded
    }

    /// Add a bonded device
    pub(crate) fn add_bond_information(&self, bond_information: BondInformation) -> Result<(), Error> {
        trace!("[security manager] Add bond for {:?}", bond_information.identity);
        let index = self
            .state
            .borrow()
            .bond
            .iter()
            .position(|bond| bond_information.identity.match_identity(&bond.identity));
        match index {
            Some(index) => {
                // Replace existing bond if it exists
                self.state.borrow_mut().bond[index] = bond_information;
                Ok(())
            }
            None => self
                .state
                .borrow_mut()
                .bond
                .push(bond_information)
                .map_err(|_| Error::OutOfMemory),
        }
    }

    /// Remove a bonded device
    pub(crate) fn remove_bond_information(&self, identity: Identity) -> Result<(), Error> {
        trace!("[security manager] Remove bond for {:?}", identity);
        let index = self
            .state
            .borrow_mut()
            .bond
            .iter()
            .position(|bond| bond.identity.match_identity(&identity));
        match index {
            Some(index) => {
                self.state.borrow_mut().bond.remove(index);
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Get bonded devices
    pub(crate) fn get_bond_information(&self) -> Vec<BondInformation, BOND_COUNT> {
        Vec::from_slice(self.state.borrow().bond.as_slice()).unwrap()
    }

    fn handle_peripheral<P: PacketPool>(&self,
                         pdu: Pdu<P::Packet>,
                         connections: &ConnectionManager<'_, P>,
                         storage: &ConnectionStorage<P::Packet>,) -> Result<(), Error>
    {
        let handle = storage.handle.ok_or(Error::InvalidValue)?;
        let peer_address_kind = storage.peer_addr_kind.ok_or(Error::InvalidValue)?;
        let peer_identity = storage.peer_identity.ok_or(Error::InvalidValue)?;
        let peer_address = Address {
            kind: peer_address_kind,
            addr: peer_identity.bd_addr,
        };
        let mut buffer = [0u8; 72];
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

        let address = {
            let mut state_machine = self.peripheral_pairing_sm.borrow_mut();
            if state_machine.is_none() {
                *state_machine = Some(Pairing::new(self.state.borrow().local_address.unwrap(), peer_address));
            }

            state_machine.as_ref().unwrap().peer_address()
        };

        if address != peer_address {
            // TODO Is this correct? 
            self.peripheral_pairing_sm.replace(None);
            return Err(Error::InvalidValue);
        }

        info!("Pairing step with new state machine!");
        let sm = {
            self.peripheral_pairing_sm.borrow()
        };
        let mut ops = pairings_ops_from_fn(handle, |tx| {
            self.try_send_packet(tx, connections, handle)
        }, |ltk: &LongTermKey| {
            info!("Enabling encryption for {}", peer_identity);
            //let bond_info = self.store_pairing()?;
            let bond_info = BondInformation {
                ltk: ltk.clone(),
                identity: peer_identity.clone(),
            };
            self.add_bond_information(bond_info.clone())?;
            self.try_send_event(SecurityEventData::EnableEncryption(handle, bond_info))
        });
        let mut rng_borrow = self.rng.borrow_mut();
        sm.as_ref().unwrap().handle(command, payload, &mut ops, rng_borrow.deref_mut())
    }

    /// Handle packet
    pub(crate) fn handle<P: PacketPool>(
        &self,
        pdu: Pdu<P::Packet>,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        // Should it be possible to handle multiple concurrent pairings?
        let role = storage.role.ok_or(Error::InvalidValue)?;

        let result = if role == LeConnRole::Peripheral {
            self.handle_peripheral(pdu, connections, storage)
        }
        else {
            todo!()
        };
        if let Err(ref error) = result {
            let reason = if let Error::Security(secuity_error) = error {
                *secuity_error
            } else {
                Reason::UnspecifiedReason
            };

            error!("Handling of command failed {:?}", error);

            // Cease sending security manager messages on timeout
            if *error != Error::Timeout {
                let handle = storage.handle.ok_or(Error::InvalidValue)?;
                let mut packet = self.prepare_packet(Command::PairingFailed, connections)?;
                let payload = packet.payload_mut();
                payload[0] = u8::from(reason);

                match self.try_send_packet(packet, connections, handle) {
                    Ok(()) => (),
                    Err(error) => {
                        error!("[security manager] Failed to send pairing failed {:?}", error);
                        return Err(error);
                    }
                }
            }
            self.pairing_result(reason)?;
        }
        result
    }

    /// Initiate pairing
    pub fn initiate<P: PacketPool>(&self, connection: &Connection<P>) -> Result<(), Error> {
        todo!()
    }

    /// Cancel pairing after timeout
    pub(crate) fn cancel_timeout(&self) -> Result<(), Error> {
        todo!()
    }

    /// Channel disconnected
    pub(crate) fn disconnect(&self, handle: ConnHandle, identity: Option<Identity>) -> Result<(), Error> {
        self.peripheral_pairing_sm.replace(None);
        if let Some(identity) = identity {
            self.state.borrow_mut().bond.retain(|x| x.identity != identity);
        }

        Ok(())
    }

    /// Handle pairing response command
    fn handle_pairing_failed(&self, payload: &[u8]) -> Result<(), Error> {
        let reason = if let Ok(r) = Reason::try_from(payload[0]) {
            r
        } else {
            Reason::UnspecifiedReason
        };
        error!("[security manager] Pairing failed {}", reason);
        self.pairing_result(reason)
    }

    /// Handle recevied events from HCI
    pub(crate) fn handle_event(&self, event: &Event) -> Result<(), Error> {
        match event {
            Event::EncryptionChangeV1(event_data) => match event_data.status.to_result() {
                Ok(()) => {
                    warn!("[security manager] Handle Encryption Changed event {}", event_data.enabled);
                }
                Err(error) => {
                    error!("[security manager] Encryption Changed Handle Error {}", error);
                }
            },
            Event::Le(LeEvent::LeLongTermKeyRequest(event_data)) => {
                self.try_send_event(SecurityEventData::SendLongTermKey(event_data.handle))?;
            }
            _ => (),
        }
        Ok(())
    }

    /// Prepare a packet for sending
    fn prepare_packet<P: PacketPool>(
        &self,
        command: Command,
        connections: &ConnectionManager<P>,
    ) -> Result<TxPacket<P>, Error> {
        let packet = P::allocate().ok_or(Error::OutOfMemory)?;
        TxPacket::new(packet, command)
    }

    /// Send a packet
    fn try_send_packet<P: PacketPool>(
        &self,
        packet: TxPacket<P>,
        connections: &ConnectionManager<P>,
        handle: ConnHandle,
    ) -> Result<(), Error> {
        let len = packet.total_size();
        trace!("[security manager] Send {} {}", packet.command, len);
        connections.try_outbound(handle, packet.into_pdu())
    }

    /// Send a packet
    fn try_send_event(&self, event: SecurityEventData) -> Result<(), Error> {
        self.events.try_send(event).map_err(|_| Error::OutOfMemory)
    }

    /// Poll for security manager work
    pub(crate) fn poll_events(
        &self,
    ) -> impl Future<Output = Result<SecurityEventData, TimeoutError>> + use<'_, BOND_COUNT> {
        // try to pop an event from the channel
        poll_fn(|cx| self.events.poll_receive(cx)).with_deadline(*self.timer_expires.borrow())
    }

    /// Long duration, to disable the timer
    const TIMEOUT_DISABLE: Duration = Duration::from_secs(31556926); // ~1 year
                                                                     // Workaround for Duration multiplication not being const
    const TIMEOUT_SECS: u64 = 30;
    /// Pairing time-out
    const TIMEOUT: Duration = Duration::from_secs(Self::TIMEOUT_SECS);
    /// Pairing time-out treshold, used to register wakeup
    const TIMER_WAKE_THRESHOLD: Duration = Duration::from_secs(Self::TIMEOUT_SECS * 2);

    /// Reset timeout timer
    #[inline]
    fn timer_reset(&self) -> Result<(), Error> {
        self.timer_expires.replace(Instant::now() + Self::TIMEOUT);
        self.try_send_event(SecurityEventData::TimerChange)
    }

    /// "disable" timeout timer
    #[inline]
    fn timer_disable(&self) -> Result<(), Error> {
        self.timer_expires.replace(Instant::now() + Self::TIMEOUT_DISABLE);
        self.try_send_event(SecurityEventData::TimerChange)
    }

    /// Update pairing result
    fn pairing_result(&self, reason: Reason) -> Result<(), Error> {
        self.timer_disable()?;
        self.result_signal.signal(reason);
        Ok(())
    }
}
