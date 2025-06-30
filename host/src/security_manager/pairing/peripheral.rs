use crate::codec::{Decode, Encode};
use crate::security_manager::constants::ENCRYPTION_KEY_SIZE_128_BITS;
use crate::security_manager::crypto::{Nonce, PublicKey, SecretKey};
use crate::security_manager::pairing::util::{
    make_dhkey_check_packet, make_pairing_random, make_public_key_packet, prepare_packet, CommandAndPayload,
};
use crate::security_manager::pairing::PairingOps;
use crate::security_manager::types::{AuthReq, BondingFlag, Command, IoCapabilities, PairingFeatures};
use crate::security_manager::{PairingData, PairingMethod, PairingState, Reason};
use crate::{Address, Error, LongTermKey, PacketPool};
use core::cell::RefCell;
use core::ops::Deref;
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
    pub fn initiate<P: PacketPool, OPS: PairingOps<P>>(
        ops: &mut OPS,
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

        Ok(Self {
            state: RefCell::new(NumericComparisonState::WaitPairingRandom),
        })
    }

    fn state(&self) -> NumericComparisonState {
        *self.state.borrow()
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

        let packet = make_pairing_random::<P>(&local_nonce)?;
        match ops.try_send_packet(packet) {
            Ok(_) => (),
            Err(error) => {
                error!("[security manager] Failed to send random {:?}", error);
                return Err(error);
            }
        }

        let vb = peer_nonce.g2(peer_public_key.x(), local_public_key.x(), &local_nonce);

        info!("** Display and compare numeric value {}", vb.0);
        // Assume ok
        {
            pairing_data.borrow_mut().peer_nonce = Some(peer_nonce);
        }

        let (mac_key, ltk) = {
            let pairing_data = pairing_data.borrow();
            let peer_address = pairing_data.peer_address.ok_or(Error::InvalidValue)?;
            let local_address = pairing_data.local_address.ok_or(Error::InvalidValue)?;
            pairing_data.dh_key.as_ref().ok_or(Error::InvalidValue)?.f5(
                peer_nonce,
                local_nonce,
                peer_address,
                local_address,
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
    ) -> Result<bool, Error> {
        match (self.state(), command.command) {
            (NumericComparisonState::WaitPairingRandom, Command::PairingRandom) => {
                self.handle_pairing_random::<P, OPS>(command.payload, ops, pairing_data)?;
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

    fn handle<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        command: CommandAndPayload,
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
        rng: &mut ChaCha12Rng,
    ) -> Result<Option<Phases>, Error> {
        let state = self.state();
        match (state, command.command) {
            (Phase1Step::WaitingPairingRequest, Command::PairingRequest) => {
                self.handle_pairing_request::<P, OPS>(command.payload, ops, pairing_data)?;
                *self.state.borrow_mut() = Phase1Step::WaitingPublicKey;
                Ok(None)
            }
            (Phase1Step::WaitingPublicKey, Command::PairingPublicKey) => {
                self.handle_public_key(command.payload, pairing_data);
                self.generate_public_private_key(pairing_data, rng);
                self.send_public_key::<P, OPS>(ops, pairing_data)?;
                self.generate_diffie_hellman_key(pairing_data)?;
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

enum Phase2Step {
    // One of numeric comparison, passkey entry or out of band (OOB) is used
    NumericComparison(NumericComparison),
    PassKeyEntry,
    OOB,
    WaitDHKeyEa,
    Done,
}

impl Phase2Step {
    pub fn handle<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        command: CommandAndPayload,
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
    ) -> Result<Option<Phase2Step>, Error> {
        match self {
            Phase2Step::NumericComparison(p) => {
                if p.handle::<P, OPS>(command, ops, pairing_data)? {
                    Ok(Some(Phase2Step::WaitDHKeyEa))
                } else {
                    Ok(None)
                }
            }
            Self::PassKeyEntry => todo!(),
            Self::OOB => todo!(),
            Self::WaitDHKeyEa => {
                self.handle_dhkey_check_ea::<P, OPS>(command, ops, pairing_data)?;
                Ok(Some(Self::Done))
            }
            Self::Done => Err(Error::InvalidState),
        }
    }

    fn handle_dhkey_check_ea<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        command: CommandAndPayload,
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
    ) -> Result<(), Error> {
        if command.command != Command::PairingDhKeyCheck {
            return Err(Error::InvalidState);
        }

        let (expected_payload, response) = {
            let pairing_data = pairing_data.borrow();
            let mac_key = pairing_data.mac_key.as_ref().ok_or(Error::InvalidValue)?;
            let peer_nonce = pairing_data.peer_nonce.ok_or(Error::InvalidValue)?;
            let local_nonce = pairing_data.local_nonce.ok_or(Error::InvalidValue)?;
            let rb = pairing_data.local_secret_r.ok_or(Error::InvalidValue)?;
            let ra = pairing_data.peer_secret_r.ok_or(Error::InvalidValue)?;
            let peer_iocap = pairing_data.peer_features.ok_or(Error::InvalidValue)?.as_io_cap();
            let local_iocap = pairing_data.local_features.ok_or(Error::InvalidValue)?.as_io_cap();
            let peer_address = pairing_data.peer_address.ok_or(Error::InvalidValue)?;
            let local_address = pairing_data.local_address.ok_or(Error::InvalidValue)?;

            (
                mac_key
                    .f6(
                        peer_nonce,
                        local_nonce,
                        rb,
                        peer_iocap.into(),
                        peer_address,
                        local_address,
                    )
                    .0
                    .to_le_bytes(),
                mac_key.f6(local_nonce, peer_nonce, ra, local_iocap, local_address, peer_address),
            )
        };

        let (bd_addr, ltk) = {
            let pairing_data = pairing_data.borrow();
            let ltk = pairing_data.ltk.ok_or(Error::InvalidValue)?;
            let address = pairing_data.peer_address.ok_or(Error::InvalidValue)?;
            (address.addr, LongTermKey(ltk))
        };

        if command.payload != expected_payload {
            return Err(Error::Security(Reason::DHKeyCheckFailed));
        }

        let packet = make_dhkey_check_packet::<P>(&response)?;
        ops.try_send_packet(packet)?;

        let handle = ops.connection_handle();
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
        Ok(Self {
            step: RefCell::new(Phase2Step::NumericComparison(NumericComparison::initiate::<P, OPS>(
                ops,
                pairing_data,
                rng,
            )?)),
        })
    }

    pub fn handle<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        command: CommandAndPayload,
        ops: &mut OPS,
        pairing_data: &RefCell<PairingData>,
    ) -> Result<Option<Phases>, Error> {
        let next_step = self.step.borrow().handle::<P, OPS>(command, ops, pairing_data)?;
        if let Some(next_step) = next_step {
            let done = matches!(next_step, Phase2Step::Done);
            *self.step.borrow_mut() = next_step;
            if done {
                // TODO should be conditional if we should send extra encryption data or not
                return Ok(Some(Phases::Done));
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

#[cfg(test)]
mod tests {
    extern crate alloc;
    use crate::security_manager::crypto::{Nonce, PublicKey, SecretKey};
    use crate::security_manager::pairing::peripheral::Pairing;
    use crate::security_manager::pairing::util::make_public_key_packet;
    use crate::security_manager::pairing::PairingOps;
    use crate::security_manager::types::{Command, IoCapabilities, PairingFeatures};
    use crate::security_manager::{PairingData, TxPacket};
    use crate::{Address, Error, LongTermKey, Packet, PacketPool};
    use bt_hci::param::ConnHandle;
    use core::cell::RefCell;
    use rand_chacha::ChaCha12Core;
    use rand_core::SeedableRng;

    #[derive(Debug)]
    struct TestPacket(heapless::Vec<u8, 128>);

    impl AsRef<[u8]> for TestPacket {
        fn as_ref(&self) -> &[u8] {
            self.0.as_slice()
        }
    }

    impl AsMut<[u8]> for TestPacket {
        fn as_mut(&mut self) -> &mut [u8] {
            self.0.as_mut_slice()
        }
    }

    impl Packet for TestPacket {}

    #[derive(Debug)]
    struct HeaplessPool;

    impl PacketPool for HeaplessPool {
        type Packet = TestPacket;
        const MTU: usize = 128;

        fn allocate() -> Option<Self::Packet> {
            let mut ret = TestPacket(heapless::Vec::new());
            ret.0.resize(Self::MTU, 0).unwrap();
            Some(ret)
        }

        fn capacity() -> usize {
            isize::MAX as usize
        }
    }

    #[derive(Default)]
    struct TestOps {
        sent_packets: heapless::Vec<TxPacket<HeaplessPool>, 10>,
        encryptions: heapless::Vec<LongTermKey, 10>,
    }

    impl PairingOps<HeaplessPool> for TestOps {
        fn try_send_packet(&mut self, packet: TxPacket<HeaplessPool>) -> Result<(), Error> {
            let _ = self.sent_packets.push(packet);
            Ok(())
        }

        fn try_enable_encryption(&mut self, ltk: &LongTermKey) -> Result<(), Error> {
            self.encryptions.push(ltk.clone()).unwrap();
            Ok(())
        }

        fn connection_handle(&mut self) -> ConnHandle {
            ConnHandle::new(2)
        }
    }

    #[test]
    fn happy_path() {
        let mut pairing_ops = TestOps::default();
        let pairing_data = RefCell::new(PairingData::new());
        let pairing = Pairing::new(
            Address::random([1, 2, 3, 4, 5, 6]),
            Address::random([7, 8, 9, 10, 11, 12]),
            &pairing_data,
        );
        let mut rng = ChaCha12Core::seed_from_u64(1).into();
        // Central sends pairing request, expects pairing response from peripheral
        pairing
            .handle::<HeaplessPool, _>(
                Command::PairingRequest,
                &[0x03, 0, 0x08, 16, 0, 0],
                &mut pairing_ops,
                &pairing_data,
                &mut rng,
            )
            .unwrap();
        {
            let sent_packets = &pairing_ops.sent_packets;
            assert_eq!(
                pairing_data.borrow().peer_features,
                Some(PairingFeatures {
                    io_capabilities: IoCapabilities::NoInputNoOutput,
                    security_properties: 8.into(),
                    ..Default::default()
                })
            );
            assert_eq!(sent_packets.len(), 1);
            let pairing_response = &sent_packets[0];
            assert_eq!(pairing_response.command, Command::PairingResponse);
            assert_eq!(pairing_response.payload(), &[0x03, 0, 12, 16, 0, 0]);
            assert_eq!(
                pairing_data.borrow().local_features,
                Some(PairingFeatures {
                    io_capabilities: IoCapabilities::NoInputNoOutput,
                    security_properties: 12.into(),
                    ..Default::default()
                })
            );
        }
        // Pairing method expected to be just works (numeric comparison)
        // Central sends public key, expects peripheral public key followed by peripheral confirm
        let secret_key = SecretKey::new(&mut rng);
        let packet = make_public_key_packet::<HeaplessPool>(&secret_key.public_key()).unwrap();
        pairing
            .handle::<HeaplessPool, _>(
                Command::PairingPublicKey,
                packet.payload(),
                &mut pairing_ops,
                &pairing_data,
                &mut rng,
            )
            .unwrap();

        {
            let sent_packets = &pairing_ops.sent_packets;
            assert_eq!(sent_packets.len(), 3);

            let peer_public = pairing_data.borrow().public_key_peer.unwrap();
            assert_eq!(peer_public, secret_key.public_key());

            let local_public = pairing_data.borrow().public_key.unwrap();
            assert_eq!(local_public, PublicKey::from_bytes(sent_packets[1].payload()));
            assert_eq!(sent_packets[1].command, Command::PairingPublicKey);
            // These magic values depends on the random number generator and the seed.
            assert_eq!(
                sent_packets[1].payload(),
                &[
                    83, 171, 46, 254, 4, 90, 134, 154, 166, 92, 149, 210, 40, 29, 13, 105, 204, 111, 93, 54, 48, 113,
                    67, 56, 159, 46, 229, 216, 65, 17, 185, 147, 105, 13, 253, 69, 206, 82, 83, 1, 1, 141, 124, 108,
                    221, 90, 7, 60, 250, 66, 190, 186, 121, 211, 140, 7, 80, 110, 58, 174, 243, 47, 255, 61
                ]
            );

            assert_eq!(sent_packets[2].command, Command::PairingConfirm);
            assert_eq!(
                sent_packets[2].payload(),
                &[27, 253, 56, 56, 116, 220, 121, 84, 160, 189, 222, 40, 163, 99, 44, 214]
            );
            let confirm = pairing_data.borrow().confirm.unwrap();
            assert_eq!(
                confirm.0,
                u128::from_le_bytes(sent_packets[2].payload().try_into().unwrap())
            );

            assert!(pairing_data.borrow().local_nonce.is_some());
        }

        // Central sends Nonce, expects Nonce
        pairing
            .handle::<HeaplessPool, _>(
                Command::PairingRandom,
                &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                &mut pairing_ops,
                &pairing_data,
                &mut rng,
            )
            .unwrap();

        {
            let pairing_data = pairing_data.borrow();
            let sent_packets = &pairing_ops.sent_packets;
            let peer_nonce = Nonce(u128::from_le_bytes([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            ]));
            let local_nonce = pairing_data.local_nonce.unwrap().0.to_le_bytes();
            assert_eq!(sent_packets.len(), 4);
            assert_eq!(sent_packets[3].command, Command::PairingRandom);
            assert_eq!(sent_packets[3].payload(), &local_nonce);
            assert_eq!(pairing_data.peer_nonce, Some(peer_nonce));
            assert!(pairing_data.mac_key.is_some());
            assert!(pairing_data.ltk.is_some());
            assert_eq!(pairing_ops.encryptions.len(), 0);
        }
        pairing
            .handle::<HeaplessPool, _>(
                Command::PairingDhKeyCheck,
                &[
                    0x70, 0xa9, 0xf1, 0xd0, 0xcf, 0x52, 0x84, 0xe9, 0xfc, 0x36, 0x9b, 0x84, 0x35, 0x13, 0xc5, 0xed,
                ],
                &mut pairing_ops,
                &pairing_data,
                &mut rng,
            )
            .unwrap();

        {
            let pairing_data = pairing_data.borrow();
            let sent_packets = &pairing_ops.sent_packets;
            let local_nonce = pairing_data.local_nonce.unwrap().0.to_le_bytes();
            assert_eq!(sent_packets.len(), 5);
            assert_eq!(sent_packets[4].command, Command::PairingDhKeyCheck);
            assert_eq!(
                sent_packets[4].payload(),
                [22, 123, 0, 74, 239, 81, 163, 188, 71, 111, 251, 117, 54, 186, 205, 3]
            );
            assert_eq!(pairing_ops.encryptions.len(), 1);
            assert!(matches!(
                pairing_ops.encryptions[0],
                LongTermKey(_)
            ));
        }
    }
}
