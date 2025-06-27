use crate::security_manager::crypto::Nonce;
use core::cell::RefCell;

mod util {
    use crate::connection_manager::ConnectionManager;
    use crate::pdu::Pdu;
    use crate::security_manager::crypto::Nonce;
    use crate::security_manager::types::Command;
    use crate::security_manager::{Reason, TxPacket};
    use crate::{Error, PacketPool};
    use bt_hci::param::ConnHandle;

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

    pub fn try_send_packet<P: PacketPool>(
        packet: TxPacket<P>,
        connections: &ConnectionManager<P>,
        handle: ConnHandle,
    ) -> Result<(), Error> {
        let len = packet.total_size();
        trace!("[security manager] Send {} {}", packet.command, len);
        connections.try_outbound(handle, packet.into_pdu())
    }

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
}

mod central {
    use crate::connection_manager::{ConnectionManager, ConnectionStorage};
    use crate::pdu::Pdu;
    use crate::security_manager::crypto::{Confirm, Nonce};
    use crate::security_manager::state::util::{prepare_packet, try_send_packet, CommandAndPayload};
    use crate::security_manager::types::Command;
    use crate::security_manager::{PairingData, PairingState, Reason};
    use crate::{Error, PacketPool};
    use bt_hci::param::{ConnHandle, LeConnRole};
    use core::cell::RefCell;
    use rand_chacha::ChaCha12Rng;

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    enum NumericComparisonState {
        WaitPairingConfirm,
        WaitPairingRandom,
        Done,
    }

    struct NumericComparison {
        state: RefCell<NumericComparisonState>,
    }

    impl NumericComparison {
        fn handle_pairing_confirm<P: PacketPool>(
            &self,
            payload: &[u8],
            connections: &ConnectionManager<P>,
            handle: ConnHandle,
            pairing_data: &RefCell<PairingData>,
        ) -> Result<(), Error> {
            let confirm = Confirm(u128::from_le_bytes(
                payload.try_into().map_err(|_| Error::InvalidValue)?,
            ));

            let local_nonce = match pairing_data.borrow().local_nonce {
                Some(n) => Ok(n),
                None => {
                    error!("[security manager] Uninitialized nonce");
                    Err(Error::InvalidValue)
                }
            }?;

            let packet = super::util::make_pairing_random::<P>(&local_nonce)?;

            match try_send_packet(packet, connections, handle) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to send random {:?}", error);
                    return Err(error);
                }
            }

            {
                pairing_data.borrow_mut().confirm = Some(confirm);
            }

            Ok(())
        }

        fn handle_pairing_random(&self, payload: &[u8], pairing_data: &RefCell<PairingData>) -> Result<(), Error> {
            let peer_nonce = Nonce(u128::from_le_bytes(
                payload
                    .try_into()
                    .map_err(|_| Error::Security(Reason::InvalidParameters))?,
            ));

            let (local_nonce, peer_public_key, local_public_key, peer_confirm) = {
                let pairing_data = pairing_data.borrow();
                let local_nonce = pairing_data.local_nonce.ok_or(Error::InvalidValue)?;
                let peer_public_key = pairing_data.public_key_peer.ok_or(Error::InvalidValue)?;
                let local_public_key = pairing_data.public_key.ok_or(Error::InvalidValue)?;
                let peer_confirm = pairing_data.confirm.ok_or(Error::InvalidValue)?;
                (local_nonce, peer_public_key, local_public_key, peer_confirm)
            };

            // Calculate and check confirm
            let local_confirm = peer_nonce.f4(peer_public_key.x(), local_public_key.x(), 0);
            if local_confirm != peer_confirm {
                return Err(Error::Security(Reason::ConfirmValueFailed));
            }

            let vb = local_nonce.g2(local_public_key.x(), peer_public_key.x(), &peer_nonce);

            info!("** Display and compare numeric value {}", vb.0);
            // Assume ok
            Ok(())
        }

        fn state(&self) -> NumericComparisonState {
            *self.state.borrow()
        }

        pub fn new(pairing_data: &RefCell<PairingData>, rng: &mut ChaCha12Rng) -> Self {
            let local_nonce = Nonce::new(rng);
            pairing_data.borrow_mut().local_nonce = Some(local_nonce);
            Self {
                state: RefCell::new(NumericComparisonState::WaitPairingConfirm),
            }
        }

        pub fn handle<P: PacketPool>(
            &self,
            pdu: Pdu<P::Packet>,
            connections: &ConnectionManager<'_, P>,
            handle: ConnHandle,
            pairing_data: &RefCell<PairingData>,
        ) -> Result<bool, Error> {
            let mut buffer = [0u8; 72];
            let parsed = CommandAndPayload::try_parse::<P>(pdu, &mut buffer)?;
            match (self.state(), parsed.command) {
                (NumericComparisonState::WaitPairingConfirm, Command::PairingConfirm) => {
                    self.handle_pairing_confirm(parsed.payload, connections, handle, pairing_data)?;
                    *self.state.borrow_mut() = NumericComparisonState::WaitPairingRandom;
                    Ok(false)
                }
                (NumericComparisonState::WaitPairingRandom, Command::PairingRandom) => {
                    self.handle_pairing_random(parsed.payload, pairing_data)?;
                    *self.state.borrow_mut() = NumericComparisonState::Done;
                    Ok(true)
                }
                _ => Err(Error::Security(Reason::InvalidParameters)),
            }
        }
    }

    pub enum Phase2 {
        NumericComparison(NumericComparison),
    }
}

mod peripheral {
    use crate::codec::{Decode, Encode};
    use crate::connection_manager::ConnectionManager;
    use crate::pdu::Pdu;
    use crate::security_manager::constants::ENCRYPTION_KEY_SIZE_128_BITS;
    use crate::security_manager::crypto::{Nonce, PublicKey, SecretKey};
    use crate::security_manager::state::util::{prepare_packet, try_send_packet, CommandAndPayload};
    use crate::security_manager::types::{AuthReq, BondingFlag, Command, IoCapabilities, PairingFeatures};
    use crate::security_manager::{PairingData, PairingMethod, PairingState, Reason};
    use crate::{Error, LongTermKey, PacketPool};
    use bt_hci::param::{ConnHandle, LeConnRole};
    use core::cell::RefCell;
    use rand_chacha::ChaCha12Rng;

    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    enum NumericComparisonState {
        WaitPairingRandom,
        Done,
    }
    pub struct NumericComparison {
        state: RefCell<NumericComparisonState>,
    }

    impl NumericComparison {
        pub fn initiate<P: PacketPool>(
            connections: &ConnectionManager<'_, P>,
            handle: ConnHandle,
            pairing_data: &RefCell<PairingData>,
            rng: &mut ChaCha12Rng,
        ) -> Result<Self, Error> {
            let local_nonce = Nonce::new(rng);
            let (local_public_key, peer_public_key) = {
                let pairing_data = pairing_data.borrow();
                let local_public_key = pairing_data.public_key.ok_or(Error::InvalidValue)?;
                let peer_public_key = pairing_data.public_key_peer.ok_or(Error::InvalidValue)?;
                (local_public_key, peer_public_key)
            };
            let confirm = local_nonce.f4(local_public_key.x(), peer_public_key.x(), 0);

            let mut packet = prepare_packet::<P>(Command::PairingConfirm)?;
            let response = packet.payload_mut();
            response.copy_from_slice(&confirm.0.to_le_bytes());
            match try_send_packet(packet, connections, handle) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to send confirm {:?}", error);
                    return Err(error);
                }
            }

            {
                let mut pairing_data = pairing_data.borrow_mut();
                pairing_data.local_nonce = Some(local_nonce);
                pairing_data.confirm = Some(confirm);
            }

            Ok(Self {
                state: RefCell::new(NumericComparisonState::WaitPairingRandom),
            })
        }

        fn state(&self) -> NumericComparisonState {
            *self.state.borrow()
        }

        fn handle_pairing_random<P: PacketPool>(
            &self,
            payload: &[u8],
            connections: &ConnectionManager<P>,
            handle: ConnHandle,
            pairing_data: &RefCell<PairingData>,
        ) -> Result<(), Error> {
            let peer_nonce = Nonce(u128::from_le_bytes(
                payload
                    .try_into()
                    .map_err(|_| Error::Security(Reason::InvalidParameters))?,
            ));

            let (peer_nonce, local_nonce, peer_public_key, local_public_key, peer_confirm) = {
                let pairing_data = pairing_data.borrow();
                let peer_nonce = pairing_data.peer_nonce.ok_or(Error::InvalidValue)?;
                let local_nonce = pairing_data.local_nonce.ok_or(Error::InvalidValue)?;
                let peer_public_key = pairing_data.public_key_peer.ok_or(Error::InvalidValue)?;
                let local_public_key = pairing_data.public_key.ok_or(Error::InvalidValue)?;
                let peer_confirm = pairing_data.confirm.ok_or(Error::InvalidValue)?;
                (peer_nonce, local_nonce, peer_public_key, local_public_key, peer_confirm)
            };

            let packet = super::util::make_pairing_random::<P>(&local_nonce)?;
            match try_send_packet(packet, connections, handle) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to send random {:?}", error);
                    return Err(error);
                }
            }

            let vb = peer_nonce.g2(peer_public_key.x(), local_public_key.x(), &local_nonce);

            info!("** Display and compare numeric value {}", vb.0);
            // Assume ok

            let (mac_key, ltk) = {
                let pairing_data = pairing_data.borrow();
                let peer_address = pairing_data.peer_address.ok_or(Error::InvalidValue)?;
                let local_address = todo!();
                pairing_data.dh_key.as_ref().ok_or(Error::InvalidValue)?.f5(peer_nonce, local_nonce, peer_address, local_address)
            };

            {
                let mut pairing_data = pairing_data.borrow_mut();
                pairing_data.ltk = Some(ltk.0);
                pairing_data.mac_key = Some(mac_key);
            }

            Ok(())
        }

        pub fn handle<P: PacketPool>(
            &self,
            pdu: Pdu<P::Packet>,
            connections: &ConnectionManager<'_, P>,
            handle: ConnHandle,
            pairing_data: &RefCell<PairingData>,
        ) -> Result<bool, Error> {
            let mut buffer = [0u8; 72];
            let parsed = CommandAndPayload::try_parse::<P>(pdu, &mut buffer)?;
            match (self.state(), parsed.command) {
                (NumericComparisonState::WaitPairingRandom, Command::PairingRandom) => {
                    self.handle_pairing_random(parsed.payload, connections, handle, pairing_data)?;
                    *self.state.borrow_mut() = NumericComparisonState::Done;
                    Ok(true)
                }
                _ => Err(Error::Security(Reason::InvalidParameters)),
            }
        }
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Phase1Step {
        // Idle state, waiting for pairing request to be received
        WaitingPairingRequest,
        // Pairing request received
        // Pairing response sent
        // Waiting for public key from central
        WaitingPublicKey,
        // Central public key received
        // ECDSA private/public key generated
        // public key sent to central
        // Diffie hellman key generated
        // Authentication method chosen
        Done,
    }

    pub struct Phase1 {
        state: RefCell<Phase1Step>,
    }

    impl Phase1 {
        pub fn new() -> Self {
            Self {
                state: RefCell::new(Phase1Step::WaitingPairingRequest),
            }
        }

        pub fn handle<P: PacketPool>(
            &self,
            pdu: Pdu<P::Packet>,
            connections: &ConnectionManager<'_, P>,
            handle: ConnHandle,
            pairing_data: &RefCell<PairingData>,
            rng: &mut ChaCha12Rng,
        ) -> Result<Option<Phases>, Error> {
            let mut buffer = [0u8; 72];
            let parsed = CommandAndPayload::try_parse::<P>(pdu, &mut buffer)?;
            let state = self.state();
            match (state, parsed.command) {
                (Phase1Step::WaitingPairingRequest, Command::PairingRequest) => {
                    self.handle_pairing_request(parsed.payload, connections, handle, pairing_data)?;
                    *self.state.borrow_mut() = Phase1Step::WaitingPublicKey;
                    Ok(None)
                }
                (Phase1Step::WaitingPublicKey, Command::PairingPublicKey) => {
                    self.handle_public_key(parsed.payload, pairing_data);
                    self.generate_public_private_key(pairing_data, rng);
                    self.send_public_key(connections, handle, pairing_data)?;
                    self.generate_diffie_hellman_key(pairing_data)?;
                    let phase2_init = NumericComparison::initiate(connections, handle, pairing_data, rng)?;
                    *self.state.borrow_mut() = Phase1Step::Done;
                    Ok(Some(Phases::Phase2(Phase2::numeric_comparison(connections, handle, pairing_data, rng)?)))
                }
                _ => Err(Error::Security(Reason::InvalidParameters)),
            }
        }

        fn generate_public_private_key(&self, pairing_data: &RefCell<PairingData>, rng: &mut ChaCha12Rng) {
            let secret_key = SecretKey::new(rng);
            let public_key = secret_key.public_key();
            let mut pairing_data = pairing_data.borrow_mut();
            pairing_data.public_key = Some(public_key);
            pairing_data.secret_key = Some(secret_key);
        }

        fn state(&self) -> Phase1Step {
            *self.state.borrow()
        }

        fn handle_pairing_request<P: PacketPool>(
            &self,
            payload: &[u8],
            connections: &ConnectionManager<P>,
            handle: ConnHandle,
            pairing_data: &RefCell<PairingData>,
        ) -> Result<(), Error> {
            let peer_features =
                PairingFeatures::decode(payload).map_err(|_| Error::Security(Reason::InvalidParameters))?;
            if peer_features.maximum_encryption_key_size < ENCRYPTION_KEY_SIZE_128_BITS {
                return Err(Error::Security(Reason::EncryptionKeySize));
            }
            if !peer_features.security_properties.secure_connection() {
                return Err(Error::Security(Reason::UnspecifiedReason));
            }
            let mut local_features = PairingFeatures {
                io_capabilities: IoCapabilities::NoInputNoOutput,
                security_properties: AuthReq::new(BondingFlag::NoBonding),
                ..Default::default()
            };

            // Set identity key flag
            if peer_features.initiator_key_distribution.identity_key() {
                local_features.initiator_key_distribution.set_identity_key();
            }

            {
                let pairing_state = pairing_data.borrow();

                let mut packet = prepare_packet(Command::PairingResponse)?;

                let response = packet.payload_mut();
                local_features.encode(response).map_err(|_| Error::InvalidValue)?;

                match try_send_packet(packet, connections, handle) {
                    Ok(()) => (),
                    Err(error) => {
                        error!("[security manager] Failed to respond to request {:?}", error);
                        return Err(error);
                    }
                }
            }

            {
                let mut pairing_data = pairing_data.borrow_mut();
                pairing_data.local_features = Some(local_features);
                pairing_data.peer_features = Some(peer_features);
                pairing_data.handle = Some(handle);
                pairing_data.state = PairingState::Response;
                pairing_data.method = PairingMethod::LeSecureConnectionNumericComparison;
                //choose_pairing_method(&pairing_data.local_features, &pairing_data.peer_features);
            }

            Ok(())
        }

        fn send_public_key<P: PacketPool>(
            &self,
            connections: &ConnectionManager<P>,
            handle: ConnHandle,
            pairing_data: &RefCell<PairingData>,
        ) -> Result<(), Error> {
            let (x, y) = {
                let pairing_data = pairing_data.borrow();
                let mut x = [0u8; 32];
                let mut y = [0u8; 32];
                x.copy_from_slice(
                    pairing_data
                        .public_key
                        .as_ref()
                        .ok_or(Error::InvalidValue)?
                        .x
                        .as_be_bytes(),
                );
                y.copy_from_slice(
                    pairing_data
                        .public_key
                        .as_ref()
                        .ok_or(Error::InvalidValue)?
                        .y
                        .as_be_bytes(),
                );
                x.reverse();
                y.reverse();
                (x, y)
            };
            let mut packet = prepare_packet(Command::PairingPublicKey)?;

            let response = packet.payload_mut();

            response[..x.len()].copy_from_slice(&x);
            response[x.len()..y.len() + x.len()].copy_from_slice(&y);

            match try_send_packet(packet, connections, handle) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to send public key {:?}", error);
                    return Err(error);
                }
            }

            Ok(())
        }

        fn handle_public_key(&self, payload: &[u8], pairing_data: &RefCell<PairingData>) {
            let peer_public_key = PublicKey::from_bytes(payload);
            pairing_data.borrow_mut().public_key_peer = Some(peer_public_key);
        }

        fn generate_diffie_hellman_key(&self, pairing_data: &RefCell<PairingData>) -> Result<(), Error> {
            let dh_key = {
                let pairing_data = pairing_data.borrow();
                let secret_key = pairing_data.secret_key.as_ref().ok_or(Error::InvalidValue)?;
                let peer_public_key = pairing_data.public_key_peer.as_ref().ok_or(Error::InvalidValue)?;
                match secret_key.dh_key(*peer_public_key) {
                    Some(dh_key) => Ok(dh_key),
                    None => Err(Error::Security(Reason::InvalidParameters)),
                }?
            };

            {
                let mut pairing_data = pairing_data.borrow_mut();
                pairing_data.dh_key = Some(dh_key);
            }
            Ok(())
        }
    }

    enum Phase2Step {
        // One of numeric comparison, passkey entry or out of band (OOB) is used
        NumericComparison(NumericComparison),
        PassKeyEntry,
        OOB,
        WaitDHKeyEa,
        Done,
    }


    impl Phase2Step {
        pub fn handle<P: PacketPool>(
            &self,
            pdu: Pdu<P::Packet>,
            connections: &ConnectionManager<'_, P>,
            handle: ConnHandle,
            pairing_data: &RefCell<PairingData>,
        ) -> Result<Option<Phase2Step>, Error> {
            match self {
                Phase2Step::NumericComparison(p) => {
                    if p.handle(pdu, connections, handle, pairing_data)? {
                        Ok(Some(Phase2Step::WaitDHKeyEa))
                    } else {
                        Ok(None)
                    }
                }
                Self::PassKeyEntry => todo!(),
                Self::OOB => todo!(),
                Self::WaitDHKeyEa => todo!(),
                Self::Done => Err(Error::InvalidState),
            }
        }
    }

    struct Phase2 {
        step: RefCell<Phase2Step>,
    }

    impl Phase2 {
        fn numeric_comparison<P: PacketPool>(connections: &ConnectionManager<P>, handle: ConnHandle,
                                             pairing_data: &RefCell<PairingData>,
                                             rng: &mut ChaCha12Rng, ) -> Result<Self, Error> {
            Ok(Self {
                step: RefCell::new(Phase2Step::NumericComparison(NumericComparison::initiate(connections, handle, pairing_data, rng)?))
            })
        }

        pub fn handle<P: PacketPool>(
            &self,
            pdu: Pdu<P::Packet>,
            connections: &ConnectionManager<'_, P>,
            handle: ConnHandle,
            pairing_data: &RefCell<PairingData>, ) -> Result<Option<Phases>, Error>
        {
            let next_step = self.step.borrow().handle(pdu, connections, handle, pairing_data)?;
            if let Some(next_step) = next_step {
                let done = matches!(next_step, Phase2Step::Done);
                *self.step.borrow_mut() = next_step;
                if done {
                    return Ok(Some(Phases::Phase3));
                }
            }
            Ok(None)
        }
    }

    enum Phases {
        Phase1(Phase1),
        Phase2(Phase2),
        Phase3,
        Done,
    }

    pub struct Pairing {
        phase: RefCell<Phases>,
    }

    impl Pairing {
        pub fn new() -> Self {
            let phase1 = Phase1::new();
            Self {
                phase: RefCell::new(Phases::Phase1(phase1))
            }
        }

        pub fn handle<P: PacketPool>(&self, pdu: Pdu<P::Packet>,
                                     connections: &ConnectionManager<'_, P>,
                                     handle: ConnHandle,
                                     pairing_data: &RefCell<PairingData>,
                                     rng: &mut ChaCha12Rng, ) -> Result<(), Error> {
            let next_phase = {
                let phase = self.phase.borrow();
                match &*phase {
                    Phases::Phase1(p1) => {
                        p1.handle(pdu, connections, handle, pairing_data, rng)
                    }
                    Phases::Phase2(p2) => {
                        p2.handle(pdu, connections, handle, pairing_data)
                    }
                    Phases::Phase3 => todo!(),
                    Phases::Done => Err(Error::InvalidValue),
                }?
            };

            if let Some(next) = next_phase {
                *self.phase.borrow_mut() = next;
            }

            Ok(())
        }
    }
}
