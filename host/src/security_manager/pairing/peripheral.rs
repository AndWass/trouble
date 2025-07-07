use crate::codec::{Decode, Encode};
use crate::security_manager::constants::ENCRYPTION_KEY_SIZE_128_BITS;
use crate::security_manager::crypto::{Confirm, DHKey, MacKey, Nonce, PublicKey, SecretKey};
use crate::security_manager::pairing::util::{
    make_dhkey_check_packet, make_pairing_random, make_public_key_packet, prepare_packet, CommandAndPayload,
};
use crate::security_manager::pairing::{Event, PairingOps};
use crate::security_manager::types::{AuthReq, BondingFlag, Command, IoCapabilities, PairingFeatures};
use crate::security_manager::{Reason};
use crate::{Address, Error, LongTermKey, PacketPool};
use core::cell::RefCell;
use core::ops::{DerefMut};
use rand_chacha::ChaCha12Rng;
use rand_core::RngCore;
use crate::connection::SecurityLevel;
use crate::host::EventHandler;

#[derive(Debug, Clone)]
enum Step {
    WaitingPairingRequest,
    WaitingPublicKey,
    // Numeric comparison
    WaitingNumericComparisonRandom(NumericCompareConfirmSentTag),
    WaitingNumericComparisonResult,
    // TODO add pass key entry and OOB
    WaitingDHKeyEa,
    WaitingLinkEncrypted,
    Success,
    Error(Error),
}

#[derive(Debug, Clone)]
struct NumericCompareConfirmSentTag {}

impl NumericCompareConfirmSentTag {
    fn new<P: PacketPool, OPS: PairingOps<P>, RNG: RngCore>(
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        pairing_data.local_nonce = Nonce::new(rng);
        pairing_data.confirm = Self::compute_confirm(pairing_data)?;
        let mut packet = prepare_packet::<P>(Command::PairingConfirm)?;
        let response = packet.payload_mut();
        response.copy_from_slice(&pairing_data.confirm.0.to_le_bytes());
        match ops.try_send_packet(packet) {
            Ok(_) => (),
            Err(error) => {
                error!("[security manager] Failed to send confirm {:?}", error);
                return Err(error);
            }
        }

        Ok(Self {})
    }
    fn compute_confirm(pairing_data: &PairingData) -> Result<Confirm, Error> {
        let local_public_key = pairing_data.local_public_key.as_ref().ok_or(Error::InvalidValue)?;
        let peer_public_key = pairing_data.peer_public_key.as_ref().ok_or(Error::InvalidValue)?;
        Ok(pairing_data
            .local_nonce
            .f4(local_public_key.x(), peer_public_key.x(), 0))
    }
}

pub struct Pairing {
    current_step: RefCell<Step>,
    pairing_data: RefCell<PairingData>,
}

struct PairingData {
    local_address: Address,
    peer_address: Address,
    peer_features: PairingFeatures,
    local_features: PairingFeatures,
    peer_public_key: Option<PublicKey>,
    local_public_key: Option<PublicKey>,
    private_key: Option<SecretKey>,
    dh_key: Option<DHKey>,
    confirm: Confirm,
    local_secret_rb: u128,
    peer_secret_ra: u128,
    local_nonce: Nonce,
    peer_nonce: Nonce,
    mac_key: Option<MacKey>,
    long_term_key: LongTermKey,
}

impl Pairing {
    pub fn peer_address(&self) -> Address {
        self.pairing_data.borrow().peer_address
    }
    pub fn new(local_address: Address, peer_address: Address, requested_level: SecurityLevel) -> Self {
        let mut local_features = PairingFeatures::default();
        local_features.security_properties.set_man_in_the_middle(requested_level.authenticated());
        Self {
            current_step: RefCell::new(Step::WaitingPairingRequest),
            pairing_data: RefCell::new(PairingData {
                local_address,
                peer_address,
                local_features,
                peer_features: PairingFeatures::default(),
                peer_public_key: None,
                local_public_key: None,
                private_key: None,
                dh_key: None,
                confirm: Confirm(0),
                local_secret_rb: 0,
                peer_secret_ra: 0,
                local_nonce: Nonce(0),
                peer_nonce: Nonce(0),
                mac_key: None,
                long_term_key: LongTermKey(0)
            })
        }
    }

    pub fn handle_l2cap_command<P: PacketPool, OPS: PairingOps<P>>(&self, command: Command, payload: &[u8], ops: &mut OPS, rng: &mut ChaCha12Rng, event_handler: &dyn EventHandler) -> Result<(), Error> {
        match self.handle_impl(CommandAndPayload {
            payload,
            command
        }, ops, rng, event_handler)
        {
            Ok(()) => Ok(()),
            Err(error) => {
                self.current_step.replace(Step::Error(error.clone()));
                Err(error)
            },
        }
    }

    pub fn handle_event(&self, event: Event) -> Result<(), Error> {
        let current_state = self.current_step.borrow().clone();
        let next_state = match (current_state, event) {
            (Step::WaitingLinkEncrypted, Event::LinkEncrypted) => {
                // TODO send key data
                Step::Success
            },
            _ => Step::Error(Error::InvalidState),
        };

        match next_state {
            Step::Error(x) => {
                self.current_step.replace(Step::Error(x.clone()));
                Err(x)
            },
            x => {
                self.current_step.replace(x);
                Ok(())
            }
        }
    }

    fn handle_impl<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        command: CommandAndPayload,
        ops: &mut OPS,
        rng: &mut ChaCha12Rng,
        event_handler: &dyn EventHandler,
    ) -> Result<(), Error> {
        let current_step = self.current_step.borrow().clone();
        let mut pairing_data = self.pairing_data.borrow_mut();
        let pairing_data = pairing_data.deref_mut();
        let next_step = {
            match (current_step, command.command) {
                (Step::WaitingPairingRequest, Command::PairingRequest) => {
                    Self::handle_pairing_request(command.payload, ops, pairing_data, event_handler.io_capabilities())?;
                    Self::send_pairing_response(ops, pairing_data)?;
                    Step::WaitingPublicKey
                }
                (Step::WaitingPublicKey, Command::PairingPublicKey) => {
                    Self::handle_public_key(command.payload, pairing_data);
                    Self::generate_private_public_key_pair(pairing_data, rng)?;
                    Self::send_public_key(ops, pairing_data.local_public_key.as_ref().unwrap())?;
                    Step::WaitingNumericComparisonRandom(NumericCompareConfirmSentTag::new(ops, pairing_data, rng)?)
                }
                (Step::WaitingNumericComparisonRandom(_), Command::PairingRandom) => {
                    Self::handle_numeric_compare_random(command.payload, pairing_data)?;
                    Self::send_nonce(ops, &pairing_data.local_nonce)?;
                    Self::numeric_compare_confirm(event_handler, pairing_data)?;
                    // TODO potentially wait for user confirmation
                    Step::WaitingDHKeyEa
                }

                (Step::WaitingDHKeyEa, Command::PairingDhKeyCheck) => {
                    Self::compute_ltk(pairing_data)?;
                    Self::handle_dhkey_ea(command.payload, pairing_data)?;
                    Self::send_dhkey_eb(ops, pairing_data)?;
                    ops.try_enable_encryption(&pairing_data.long_term_key)?;
                    // TODO potentially send and/or receive keys after encryption has been enabled
                    Step::WaitingLinkEncrypted
                }

                _ => return Err(Error::InvalidState),
            }
        };

        self.current_step.replace(next_step);

        Ok(())
    }

    fn handle_pairing_request<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        local_io: IoCapabilities,
    ) -> Result<(), Error> {
        let peer_features = PairingFeatures::decode(payload).map_err(|_| Error::Security(Reason::InvalidParameters))?;
        if peer_features.maximum_encryption_key_size < ENCRYPTION_KEY_SIZE_128_BITS {
            return Err(Error::Security(Reason::EncryptionKeySize));
        }
        if !peer_features.security_properties.secure_connection() {
            return Err(Error::Security(Reason::UnspecifiedReason));
        }
        let local_features = PairingFeatures {
            io_capabilities: local_io,
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

        pairing_data.local_features = local_features;
        pairing_data.peer_features = peer_features;

        Ok(())
    }

    fn send_pairing_response<P: PacketPool, OPS: PairingOps<P>>(
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<(), Error> {
        let mut packet = prepare_packet::<P>(Command::PairingResponse)?;

        let response = packet.payload_mut();
        pairing_data
            .local_features
            .encode(response)
            .map_err(|_| Error::InvalidValue)?;

        match ops.try_send_packet(packet) {
            Ok(_) => {}
            Err(error) => {
                error!("[security manager] Failed to respond to request {:?}", error);
                return Err(error);
            }
        }

        Ok(())
    }

    fn handle_public_key(payload: &[u8], pairing_data: &mut PairingData) {
        let peer_public_key = PublicKey::from_bytes(payload);
        pairing_data.peer_public_key = Some(peer_public_key);
    }

    fn generate_private_public_key_pair(pairing_data: &mut PairingData, rng: &mut ChaCha12Rng) -> Result<(), Error> {
        let secret_key = SecretKey::new(rng);
        let public_key = secret_key.public_key();
        let peer_public_key = pairing_data
            .peer_public_key
            .ok_or(Error::Security(Reason::InvalidParameters))?;
        pairing_data.dh_key = Some(
            secret_key
                .dh_key(peer_public_key)
                .ok_or(Error::Security(Reason::InvalidParameters))?,
        );
        pairing_data.local_public_key = Some(public_key);
        pairing_data.private_key = Some(secret_key);

        Ok(())
    }

    fn send_public_key<P: PacketPool, OPS: PairingOps<P>>(ops: &mut OPS, public_key: &PublicKey) -> Result<(), Error> {
        let packet = make_public_key_packet::<P>(public_key).map_err(|_| Error::Security(Reason::InvalidParameters))?;

        match ops.try_send_packet(packet) {
            Ok(_) => (),
            Err(error) => {
                error!("[security manager] Failed to send public key {:?}", error);
                return Err(error);
            }
        }

        Ok(())
    }

    fn send_nonce<P: PacketPool, OPS: PairingOps<P>>(ops: &mut OPS, nonce: &Nonce) -> Result<(), Error> {
        let packet = make_pairing_random::<P>(nonce).map_err(|_| Error::Security(Reason::InvalidParameters))?;

        match ops.try_send_packet(packet) {
            Ok(_) => (),
            Err(error) => {
                error!("[security manager] Failed to send pairing random {:?}", error);
                return Err(error);
            }
        }

        Ok(())
    }

    fn handle_numeric_compare_random(payload: &[u8], pairing_data: &mut PairingData) -> Result<(), Error> {
        pairing_data.peer_nonce = Nonce(u128::from_le_bytes(
            payload
                .try_into()
                .map_err(|_| Error::Security(Reason::InvalidParameters))?,
        ));

        Ok(())
    }

    fn compute_ltk(pairing_data: &mut PairingData) -> Result<(), Error> {
        let (mac, ltk) = pairing_data.dh_key.as_ref().ok_or(Error::InvalidValue)?.f5(
            pairing_data.peer_nonce,
            pairing_data.local_nonce,
            pairing_data.peer_address,
            pairing_data.local_address,
        );

        pairing_data.mac_key = Some(mac);
        pairing_data.long_term_key = ltk;
        Ok(())
    }

    fn handle_dhkey_ea(payload: &[u8], pairing_data: &mut PairingData) -> Result<(), Error> {
        let expected_payload = pairing_data
            .mac_key
            .as_ref()
            .ok_or(Error::InvalidValue)?
            .f6(
                pairing_data.peer_nonce,
                pairing_data.local_nonce,
                pairing_data.local_secret_rb,
                pairing_data.peer_features.as_io_cap(),
                pairing_data.peer_address,
                pairing_data.local_address,
            )
            .0
            .to_le_bytes();

        if expected_payload != payload {
            Err(Error::Security(Reason::DHKeyCheckFailed))
        } else {
            Ok(())
        }
    }

    fn send_dhkey_eb<P: PacketPool, OPS: PairingOps<P>>(
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<(), Error> {
        let check = pairing_data.mac_key.as_ref().ok_or(Error::InvalidValue)?.f6(
            pairing_data.local_nonce,
            pairing_data.peer_nonce,
            pairing_data.peer_secret_ra,
            pairing_data.local_features.as_io_cap(),
            pairing_data.local_address,
            pairing_data.peer_address,
        );

        let check = make_dhkey_check_packet(&check)?;
        ops.try_send_packet(check)
    }

    fn numeric_compare_confirm(event_handler: &dyn EventHandler, pairing_data: &PairingData) -> Result<(), Error> {
        let peer_public_key = pairing_data.peer_public_key.ok_or(Error::InvalidValue)?;
        let local_public_key = pairing_data.local_public_key.ok_or(Error::InvalidValue)?;
        let vb = pairing_data.peer_nonce.g2(peer_public_key.x(), local_public_key.x(), &pairing_data.local_nonce);

        // TODO the display numeric should not always be displayed!
        event_handler.on_display_security_numeric(vb.0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use crate::security_manager::crypto::{Nonce, PublicKey, SecretKey};
    use crate::security_manager::pairing::peripheral::{Pairing};
    use crate::security_manager::pairing::util::make_public_key_packet;
    use crate::security_manager::pairing::PairingOps;
    use crate::security_manager::types::{Command, IoCapabilities, PairingFeatures};
    use crate::security_manager::{TxPacket};
    use crate::{Address, Error, LongTermKey, Packet, PacketPool};
    use bt_hci::param::ConnHandle;
    use rand_chacha::ChaCha12Core;
    use rand_core::SeedableRng;
    use crate::prelude::SecurityLevel;

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

    #[derive(Default)]
    struct EventHandler {

    }

    impl crate::host::EventHandler for EventHandler {

    }

    #[test]
    fn happy_path() {
        let mut pairing_ops = TestOps::default();
        /*let pairing_data = RefCell::new(PairingData::new());
        let pairing = Pairing::new(
            Address::random([1, 2, 3, 4, 5, 6]),
            Address::random([7, 8, 9, 10, 11, 12]),
            &pairing_data,
        );*/
        let event_handler = EventHandler::default();
        let pairing = Pairing::new(Address::random([1, 2, 3, 4, 5, 6]),
                                   Address::random([7, 8, 9, 10, 11, 12]), SecurityLevel::EncryptedNoAuth);
        let mut rng = ChaCha12Core::seed_from_u64(1).into();
        // Central sends pairing request, expects pairing response from peripheral
        pairing
            .handle_l2cap_command::<HeaplessPool, _>(
                Command::PairingRequest,
                &[0x03, 0, 0x08, 16, 0, 0],
                &mut pairing_ops,
                &mut rng,
                &event_handler
            )
            .unwrap();
        {
            let pairing_data = pairing.pairing_data.borrow();
            let sent_packets = &pairing_ops.sent_packets;
            assert_eq!(
                pairing_data.peer_features,
                PairingFeatures {
                    io_capabilities: IoCapabilities::NoInputNoOutput,
                    security_properties: 8.into(),
                    ..Default::default()
                }
            );
            assert_eq!(sent_packets.len(), 1);
            let pairing_response = &sent_packets[0];
            assert_eq!(pairing_response.command, Command::PairingResponse);
            assert_eq!(pairing_response.payload(), &[0x03, 0, 12, 16, 0, 0]);
            assert_eq!(
                pairing_data.local_features,
                PairingFeatures {
                    io_capabilities: IoCapabilities::NoInputNoOutput,
                    security_properties: 12.into(),
                    ..Default::default()
                }
            );
        }
        // Pairing method expected to be just works (numeric comparison)
        // Central sends public key, expects peripheral public key followed by peripheral confirm
        let secret_key = SecretKey::new(&mut rng);
        let packet = make_public_key_packet::<HeaplessPool>(&secret_key.public_key()).unwrap();
        pairing
            .handle_l2cap_command::<HeaplessPool, _>(
                Command::PairingPublicKey,
                packet.payload(),
                &mut pairing_ops,
                &mut rng,
                &event_handler
            )
            .unwrap();

        {
            let sent_packets = &pairing_ops.sent_packets;
            let pairing_data = pairing.pairing_data.borrow();
            assert_eq!(sent_packets.len(), 3);

            let peer_public = pairing_data.peer_public_key.unwrap();
            assert_eq!(peer_public, secret_key.public_key());

            let local_public = pairing_data.local_public_key.unwrap();
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
            let confirm = pairing_data.confirm;
            assert_eq!(
                confirm.0,
                u128::from_le_bytes(sent_packets[2].payload().try_into().unwrap())
            );
        }

        // Central sends Nonce, expects Nonce
        pairing
            .handle_l2cap_command::<HeaplessPool, _>(
                Command::PairingRandom,
                &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                &mut pairing_ops,
                &mut rng,
                &event_handler
            )
            .unwrap();

        {
            let pairing_data = pairing.pairing_data.borrow();
            let sent_packets = &pairing_ops.sent_packets;
            let peer_nonce = Nonce(u128::from_le_bytes([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            ]));
            let local_nonce = pairing_data.local_nonce.0.to_le_bytes();
            assert_eq!(sent_packets.len(), 4);
            assert_eq!(sent_packets[3].command, Command::PairingRandom);
            assert_eq!(sent_packets[3].payload(), &local_nonce);
            assert_eq!(pairing_data.peer_nonce, peer_nonce);
            assert_eq!(pairing_ops.encryptions.len(), 0);
        }
        pairing
            .handle_l2cap_command::<HeaplessPool, _>(
                Command::PairingDhKeyCheck,
                &[
                    0x70, 0xa9, 0xf1, 0xd0, 0xcf, 0x52, 0x84, 0xe9, 0xfc, 0x36, 0x9b, 0x84, 0x35, 0x13, 0xc5, 0xed,
                ],
                &mut pairing_ops,
                &mut rng,
                &event_handler
            )
            .unwrap();

        {
            let pairing_data = pairing.pairing_data.borrow();
            let sent_packets = &pairing_ops.sent_packets;
            let local_nonce = pairing_data.local_nonce.0.to_le_bytes();
            assert!(pairing_data.mac_key.is_some());
            assert_eq!(sent_packets.len(), 5);
            assert_eq!(sent_packets[4].command, Command::PairingDhKeyCheck);
            assert_eq!(
                sent_packets[4].payload(),
                [22, 123, 0, 74, 239, 81, 163, 188, 71, 111, 251, 117, 54, 186, 205, 3]
            );
            assert_eq!(pairing_ops.encryptions.len(), 1);
            assert!(matches!(pairing_ops.encryptions[0], LongTermKey(_)));
        }
    }
}
