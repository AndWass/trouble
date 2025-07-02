use crate::codec::{Decode, Encode};
use crate::security_manager::constants::ENCRYPTION_KEY_SIZE_128_BITS;
use crate::security_manager::crypto::{Confirm, Nonce, PublicKey, SecretKey};
use crate::security_manager::pairing::util::{
    make_dhkey_check_packet, make_mac_and_ltk, make_pairing_random, make_public_key_packet, prepare_packet,
    CommandAndPayload,
};
use crate::security_manager::pairing::PairingOps;
use crate::security_manager::types::{AuthReq, BondingFlag, Command, IoCapabilities, PairingFeatures};
use crate::security_manager::{PairingMethod, Reason};
use crate::{Address, Error, LongTermKey, PacketPool};
use core::cell::RefCell;
use core::ops::Deref;
use rand_chacha::ChaCha12Rng;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Phase1Step {
    // Pairing request has been sent, waiting for a pairing response
    WaitingPairingResponse,
    // Pairing response received
    // ECDSA private/public key generated
    // Public key sent
    // Waiting for public key from peripheral
    WaitingPublicKey,
    // Public key received from peripheral
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
            state: RefCell::new(Phase1Step::WaitingPairingResponse),
        }
    }

    fn handle<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        command: CommandAndPayload,
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
        rng: &mut ChaCha12Rng,
    ) -> Result<Option<Phases>, Error> {
        let state = self.state();
        match (state, command.command) {
            (Phase1Step::WaitingPairingResponse, Command::PairingResponse) => {
                //self.handle_pairing_response::<P, OPS>(command.payload, ops, pairing_data)?;
                self.generate_public_private_key(pairing_data, rng);
                self.send_public_key::<P, OPS>(ops, pairing_data)?;
                self.generate_diffie_hellman_key(pairing_data)?;
                *self.state.borrow_mut() = Phase1Step::WaitingPublicKey;
                Ok(None)
            }
            (Phase1Step::WaitingPublicKey, Command::PairingPublicKey) => {
                self.handle_public_key(command.payload, pairing_data);
                *self.state.borrow_mut() = Phase1Step::Done;
                Ok(Some(Phases::Phase2(Phase2::numeric_comparison::<P, OPS>(
                    ops,
                    pairing_data,
                    rng,
                )?)))
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

    fn handle_pairing_request<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
    ) -> Result<(), Error> {
        let peer_features = PairingFeatures::decode(payload).map_err(|_| Error::Security(Reason::InvalidParameters))?;
        if peer_features.maximum_encryption_key_size < ENCRYPTION_KEY_SIZE_128_BITS {
            return Err(Error::Security(Reason::EncryptionKeySize));
        }
        if !peer_features.security_properties.secure_connection() {
            return Err(Error::Security(Reason::UnspecifiedReason));
        }
        let local_features = PairingFeatures {
            io_capabilities: IoCapabilities::NoInputNoOutput,
            security_properties: AuthReq::new(BondingFlag::NoBonding),
            ..Default::default()
        };

        info!(
            "Received key distribution {:?}",
            peer_features.initiator_key_distribution
        );

        // Set identity key flag
        /*if peer_features.initiator_key_distribution.identity_key() {
            local_features.initiator_key_distribution.set_identity_key();
        }*/

        let handle = {
            let pairing_state = pairing_data.borrow();

            let mut packet = prepare_packet::<P>(Command::PairingResponse)?;

            let response = packet.payload_mut();
            local_features.encode(response).map_err(|_| Error::InvalidValue)?;

            match ops.try_send_packet(packet) {
                Ok(handle) => handle,
                Err(error) => {
                    error!("[security manager] Failed to respond to request {:?}", error);
                    return Err(error);
                }
            }
        };

        {
            let mut pairing_data = pairing_data.borrow_mut();
            pairing_data.local_features = Some(local_features);
            pairing_data.peer_features = Some(peer_features);
            pairing_data.state = PairingState::Response;
            pairing_data.method = PairingMethod::LeSecureConnectionNumericComparison;
            //choose_pairing_method(&pairing_data.local_features, &pairing_data.peer_features);
        }

        Ok(())
    }

    fn send_public_key<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
    ) -> Result<(), Error> {
        let packet =
            make_public_key_packet::<P>(pairing_data.borrow().public_key.as_ref().ok_or(Error::InvalidValue)?)?;

        match ops.try_send_packet(packet) {
            Ok(_) => (),
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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum NumericComparisonState {
    WaitingPairingConfirm,
    WaitPairingRandom,
    Done,
}
pub struct NumericComparison {
    state: RefCell<NumericComparisonState>,
}

impl NumericComparison {
    pub fn new<P: PacketPool, OPS: PairingOps<P>>() -> Result<Self, Error> {
        Ok(Self {
            state: RefCell::new(NumericComparisonState::WaitingPairingConfirm),
        })
    }

    fn state(&self) -> NumericComparisonState {
        *self.state.borrow()
    }

    fn handle_pairing_confirm<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
        rng: &mut ChaCha12Rng,
    ) -> Result<(), Error> {
        let local_nonce = Nonce::new(rng);
        let (local_public_key, peer_public_key) = {
            let pairing_data = pairing_data.borrow();
            let local_public_key = pairing_data.public_key.ok_or(Error::InvalidValue)?;
            let peer_public_key = pairing_data.public_key_peer.ok_or(Error::InvalidValue)?;
            (local_public_key, peer_public_key)
        };

        let confirm = Confirm(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));

        let packet = make_pairing_random(&local_nonce)?;
        match ops.try_send_packet(packet) {
            Ok(_) => (),
            Err(error) => {
                error!("[security manager] Failed to send confirm {:?}", error);
                return Err(error);
            }
        }

        {
            let mut pairing_data = pairing_data.borrow_mut();
            pairing_data.local_nonce = Some(local_nonce);
            pairing_data.confirm = Some(confirm);
            pairing_data.local_secret_r = Some(0);
            pairing_data.peer_secret_r = Some(0);
        }

        Ok(())
    }

    fn handle_pairing_random<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
    ) -> Result<(), Error> {
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

        let local_confirm = peer_nonce.f4(peer_public_key.x(), local_public_key.x(), 0);

        if local_confirm != peer_confirm {
            return Err(Error::Security(Reason::ConfirmValueFailed));
        }

        let vb = local_nonce.g2(local_public_key.x(), peer_public_key.x(), &peer_nonce);

        info!("** Display and compare numeric value {}", vb.0);

        // Assume ok
        {
            pairing_data.borrow_mut().peer_nonce = Some(peer_nonce);
        }

        let (mac_key, ltk) = {
            let pairing_data = pairing_data.borrow();
            let peer_address = pairing_data.peer_address.ok_or(Error::InvalidValue)?;
            let local_address = pairing_data.local_address.ok_or(Error::InvalidValue)?;
            make_mac_and_ltk(
                pairing_data.dh_key.as_ref().ok_or(Error::InvalidValue)?,
                &local_nonce,
                &peer_nonce,
                local_address,
                peer_address,
            )
        };

        {
            let mut pairing_data = pairing_data.borrow_mut();
            pairing_data.ltk = Some(ltk.0);
            pairing_data.mac_key = Some(mac_key);
        }

        Ok(())
    }

    pub fn handle<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        command: CommandAndPayload,
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
        rng: &mut ChaCha12Rng,
    ) -> Result<bool, Error> {
        match (self.state(), command.command) {
            (NumericComparisonState::WaitingPairingConfirm, Command::PairingConfirm) => {
                self.handle_pairing_confirm::<P, OPS>(command.payload, ops, pairing_data, rng)?;
                *self.state.borrow_mut() = NumericComparisonState::WaitPairingRandom;
                Ok(false)
            }
            (NumericComparisonState::WaitPairingRandom, Command::PairingRandom) => {
                self.handle_pairing_random::<P, OPS>(command.payload, ops, pairing_data)?;
                *self.state.borrow_mut() = NumericComparisonState::Done;
                Ok(true)
            }
            _ => Err(Error::Security(Reason::InvalidParameters)),
        }
    }
}

enum Phase2Step {
    // One of numeric comparison, passkey entry or out of band (OOB) is used
    NumericComparison(NumericComparison),
    PassKeyEntry,
    OOB,
    WaitDHKeyEb,
    Done,
}

impl Phase2Step {
    pub fn handle<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        command: CommandAndPayload,
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
        rng: &mut ChaCha12Rng,
    ) -> Result<Option<Phase2Step>, Error> {
        match self {
            Phase2Step::NumericComparison(p) => {
                if p.handle::<P, OPS>(command, ops, pairing_data, rng)? {
                    self.send_dhkey_check_ea::<P, OPS>(ops, pairing_data)?;
                    Ok(Some(Phase2Step::WaitDHKeyEb))
                } else {
                    Ok(None)
                }
            }
            Self::PassKeyEntry => todo!(),
            Self::OOB => todo!(),
            Self::WaitDHKeyEb => {
                self.handle_dhkey_check_eb::<P, OPS>(command, ops, pairing_data)?;
                Ok(Some(Self::Done))
            }
            Self::Done => Err(Error::InvalidState),
        }
    }

    fn send_dhkey_check_ea<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
    ) -> Result<(), Error> {
        let payload = {
            let pairing_data = pairing_data.borrow();
            let mac_key = pairing_data.mac_key.as_ref().ok_or(Error::InvalidValue)?;
            let peer_nonce = pairing_data.peer_nonce.ok_or(Error::InvalidValue)?;
            let local_nonce = pairing_data.local_nonce.ok_or(Error::InvalidValue)?;
            let rb = pairing_data.peer_secret_r.ok_or(Error::InvalidValue)?;
            let local_iocap = pairing_data.local_features.ok_or(Error::InvalidValue)?.as_io_cap();
            let peer_address = pairing_data.peer_address.ok_or(Error::InvalidValue)?;
            let local_address = pairing_data.local_address.ok_or(Error::InvalidValue)?;
            mac_key.f6(local_nonce, peer_nonce, rb, local_iocap, local_address, peer_address)
        };

        let packet = make_dhkey_check_packet::<P>(&payload)?;
        ops.try_send_packet(packet)?;
        Ok(())
    }

    fn handle_dhkey_check_eb<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        command: CommandAndPayload,
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
    ) -> Result<(), Error> {
        if command.command != Command::PairingDhKeyCheck {
            return Err(Error::InvalidState);
        }

        let expected_payload = {
            let pairing_data = pairing_data.borrow();
            let mac_key = pairing_data.mac_key.as_ref().ok_or(Error::InvalidValue)?;
            let peer_nonce = pairing_data.peer_nonce.ok_or(Error::InvalidValue)?;
            let local_nonce = pairing_data.local_nonce.ok_or(Error::InvalidValue)?;
            let ra = pairing_data.local_secret_r.ok_or(Error::InvalidValue)?;
            let peer_iocap = pairing_data.peer_features.ok_or(Error::InvalidValue)?.as_io_cap();
            let peer_address = pairing_data.peer_address.ok_or(Error::InvalidValue)?;
            let local_address = pairing_data.local_address.ok_or(Error::InvalidValue)?;
            mac_key
                .f6(peer_nonce, local_nonce, ra, peer_iocap, peer_address, local_address)
                .0
                .to_le_bytes()
        };

        if command.payload != expected_payload {
            return Err(Error::Security(Reason::DHKeyCheckFailed));
        }

        let ltk = {
            let pairing_data = pairing_data.borrow();
            let ltk = pairing_data.ltk.ok_or(Error::InvalidValue)?;
            LongTermKey(ltk)
        };

        ops.try_enable_encryption(&ltk)?;
        Ok(())
    }
}

struct Phase2 {
    step: RefCell<Phase2Step>,
}

impl Phase2 {
    fn numeric_comparison<P: PacketPool, OPS: PairingOps<P>>(
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
        rng: &mut ChaCha12Rng,
    ) -> Result<Self, Error> {
        /*Ok(Self {
            step: RefCell::new(Phase2Step::NumericComparison(
                crate::security_manager::pairing::peripheral::NumericComparison::initiate::<P, OPS>(
                    ops,
                    pairing_data,
                    rng,
                )?,
            )),
        })*/
        todo!()
    }

    pub fn handle<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        command: CommandAndPayload,
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
    ) -> Result<Option<Phases>, Error> {
        /*let next_step = self.step.borrow().handle::<P, OPS>(command, ops, pairing_data)?;
        if let Some(next_step) = next_step {
            let done = matches!(next_step, Phase2Step::Done);
            *self.step.borrow_mut() = next_step;
            if done {
                // TODO should be conditional if we should send extra encryption data or not
                return Ok(Some(Phases::Done));
            }
        }*/
        Ok(None)
    }
}

enum Phases {
    Phase1(Phase1),
    Phase2(Phase2),
    Phase3,
    Done,
}

#[derive(Debug, Clone)]
enum Step {
    Idle,
    // Initiate pairing
    WaitingPairingResponse,
    WaitingPublicKey,
    // Numeric comparison
    WaitingNumericComparisonPairingConfirm,
    WaitingNumericComparisonPairingRandom,
    WaitingNumericComparisonResult,
    // Pass key entry
    WaitingPassKeySecretInjection,
    WaitingPassKeyConfirm(PassKeyConfirmSentTag),
    WaitingPassKeyRandom(i32),
    // Out of band
    WaitingOOBConfirm,
    WaitingOOBPairingRandom,
    // Calculate LTK, the EaSentTag is used to ensure that the DHKey check value Ea has been sent
    // when transitioning to this state.
    WaitingDHKeyCheckEb(EHKeyEaSentTag),
    Success,
    Error(Error),
}

#[derive(Debug, Copy, Clone)]
struct PassKeyConfirmSentTag {
    round: i32,
}

#[derive(Debug, Copy, Clone)]
struct EHKeyEaSentTag {}

struct PairingStep {
    current_step: RefCell<Step>,
}

impl PairingStep {
    fn handle_packet<P: PacketPool, OPS: PairingOps<P>>(&self, command: CommandAndPayload) {
        if self.is_error() {
            return;
        }

        let current_step = self.current_step.borrow().clone();
        let next_step = match (current_step, command.command) {
            (Step::WaitingPairingResponse, Command::PairingResponse) => {
                //self.handle_pairing_response(command)?;
                //self.generate_private_public_key();
                //self.send_pairing_public_key(command)?;
                Step::WaitingPublicKey
            }
            (Step::WaitingPublicKey, Command::PairingPublicKey) => {
                // self.handle_public_key(command)?;
                // self.select_pairing_method()?
                Step::WaitingNumericComparisonPairingConfirm
            }
            // Numeric comparison
            (Step::WaitingNumericComparisonPairingConfirm, Command::PairingConfirm) => {
                // self.handle_numeric_comparison_pairing_confirm(command)?;
                // self.generate_nonce();
                // self.send_nonce()?;
                Step::WaitingNumericComparisonPairingRandom
            }
            (Step::WaitingNumericComparisonPairingRandom, Command::PairingRandom) => {
                // self.handle_numeric_comparison_random(command)?;
                if !self.need_numeric_comparison_result() {
                    // Step::WaitingDHKeyCheckEb(EHKeyEaSentTag::new())
                    todo!()
                } else {
                    Step::WaitingNumericComparisonResult
                }
            }

            // Pass key entry
            (Step::WaitingPassKeyConfirm(s), Command::PairingConfirm) => {
                // self.handle_pass_key_confir(s, command)?;
                // self.send_nonce()?;
                Step::WaitingPassKeyRandom(s.round)
            }

            (Step::WaitingPassKeyRandom(s), Command::PairingRandom) =>
                {
                    // self.handle_pass_key_random(s, command)?;
                    if s == 20 {
                        // Step::WaitingDHKeyCheckEb(EHKeyEaSentTag::new())
                        todo!()
                    } else {
                        // self.generate_nonce();
                        // Step::WaitingPassKeyConfirm(PassKeyConfirmSentTag::new(s+1))
                        todo!()
                    }
                }

            // Out of band
            (Step::WaitingOOBPairingRandom, Command::PairingRandom) => {
                todo!()
            }

            // Authentication potentially complete
            (Step::WaitingDHKeyCheckEb(_), Command::PairingDhKeyCheck) => {
                todo!()
            }

            _ => {
                todo!()
            }
        };

        self.current_step.replace(next_step);
    }

    pub fn handle_numeric_comparison_result(&self, matches: bool) {
        if self.is_error() {
            return;
        }

        let next_state = if !matches {
            // TODO should we send something?
            Step::Error(Error::Security(Reason::NumericComparisonFailed))
        } else {
            let current_step = self.current_step.borrow().clone();
            match current_step {
                Step::WaitingNumericComparisonResult => {
                    // Step::WaitingDHKeyCheckEb(EHKeyEaSentTag::new())
                    todo!()
                },
                _ => {
                    panic!("Invalid state")
                }
            }
        };
        self.current_step.replace(next_state);
    }

    fn is_error(&self) -> bool {
        matches!(self.current_step.borrow().deref(), Step::Error(_))
    }

    fn need_numeric_comparison_result(&self) -> bool {
        todo!()
    }
}

pub struct Pairing {
    phase: RefCell<Phases>,
}

impl Pairing {
    pub fn new(local_address: Address, peer_address: Address, pairing_data: &RefCell<PairingData>) -> Self {
        {
            let mut pairing_data = pairing_data.borrow_mut();
            pairing_data.local_address = Some(local_address);
            pairing_data.peer_address = Some(peer_address);
        }
        let phase1 = Phase1::new();
        Self {
            phase: RefCell::new(Phases::Phase1(phase1)),
        }
    }

    pub fn handle<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        command: Command,
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
        rng: &mut ChaCha12Rng,
    ) -> Result<(), Error> {
        let parsed_command = CommandAndPayload { command, payload };
        let next_phase = {
            let phase = self.phase.borrow();
            match phase.deref() {
                Phases::Phase1(p1) => p1.handle::<P, OPS>(parsed_command, ops, pairing_data, rng),
                Phases::Phase2(p2) => p2.handle::<P, OPS>(parsed_command, ops, pairing_data),
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
