package org.meadowhawk.signal

import org.whispersystems.libsignal.IdentityKey
import org.whispersystems.libsignal.IdentityKeyPair
import org.whispersystems.libsignal.InvalidKeyIdException
import org.whispersystems.libsignal.SessionBuilder
import org.whispersystems.libsignal.SessionCipher
import org.whispersystems.libsignal.SignalProtocolAddress
import org.whispersystems.libsignal.ecc.Curve
import org.whispersystems.libsignal.ecc.ECKeyPair
import org.whispersystems.libsignal.protocol.CiphertextMessage
import org.whispersystems.libsignal.protocol.PreKeySignalMessage
import org.whispersystems.libsignal.state.IdentityKeyStore
import org.whispersystems.libsignal.state.PreKeyBundle
import org.whispersystems.libsignal.state.PreKeyRecord
import org.whispersystems.libsignal.state.SessionRecord
import org.whispersystems.libsignal.state.SignalProtocolStore
import org.whispersystems.libsignal.state.SignedPreKeyRecord
import org.whispersystems.libsignal.state.impl.InMemoryIdentityKeyStore
import org.whispersystems.libsignal.state.impl.InMemoryPreKeyStore
import org.whispersystems.libsignal.state.impl.InMemorySessionStore
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore
import org.whispersystems.libsignal.state.impl.InMemorySignedPreKeyStore
import org.whispersystems.libsignal.util.KeyHelper
import org.whispersystems.libsignal.util.Medium

import java.security.InvalidKeyException

class SignalEncryptionTest {

    private static final SignalProtocolAddress BOB_ADDRESS   = new SignalProtocolAddress("+14151231234", 1);
    private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("+14159998888", 1);

    private static final ECKeyPair aliceSignedPreKey = Curve.generateKeyPair();
    private static final ECKeyPair bobSignedPreKey   = Curve.generateKeyPair();

    private static final int aliceSignedPreKeyId = new Random().nextInt(Medium.MAX_VALUE);
    private static final int bobSignedPreKeyId   = new Random().nextInt(Medium.MAX_VALUE);

    static IdentityKeyPair bobsIdentityKeyPair = KeyHelper.generateIdentityKeyPair()
    static IdentityKeyPair alicesIdentityKeyPair = KeyHelper.generateIdentityKeyPair()

    static Integer bobsRegistrationId= KeyHelper.generateRegistrationId(false)

    static SignalProtocolStore aliceStore = new InMemorySignalProtocolStore(alicesIdentityKeyPair, aliceSignedPreKeyId)
    static SignalProtocolStore bobStore = new InMemorySignalProtocolStore(bobsIdentityKeyPair, bobsRegistrationId)

    static void main(String[] args) {
        String message = (args.length >0 && args[0] != null)? args[0] : "This is  a test"

        SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
        SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

        PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
        SessionBuilder bobSessionBuilder   = new SessionBuilder(bobStore, ALICE_ADDRESS);

        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

        aliceSessionBuilder.process(bobPreKeyBundle);
        bobSessionBuilder.process(alicePreKeyBundle);

        CiphertextMessage messageForBob   = aliceSessionCipher.encrypt("hey there".getBytes());
        CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        println "ENC_MEssage for Bob = " + messageForBob.getType() + " | " + messageForBob.serialize()
         println "ENC_MEssage for Alice = " + messageForAlice.getType() + " | " + messageForAlice.serialize()

        //do message sends
        byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
        byte[] bobPlaintext   = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

        println "Alice's message = " +  new String(alicePlaintext)
        println "Bobs's message = " +  new String(bobPlaintext)

    }

     static PreKeyBundle createAlicePreKeyBundle(SignalProtocolStore aliceStore) throws InvalidKeyException {
        ECKeyPair aliceUnsignedPreKey   = Curve.generateKeyPair();
        int       aliceUnsignedPreKeyId = new Random().nextInt(Medium.MAX_VALUE);
        byte[]    aliceSignature        = Curve.calculateSignature(aliceStore.getIdentityKeyPair().getPrivateKey(),
                aliceSignedPreKey.getPublicKey().serialize());

        PreKeyBundle alicePreKeyBundle = new PreKeyBundle(1, 1,
                aliceUnsignedPreKeyId, aliceUnsignedPreKey.getPublicKey(),
                aliceSignedPreKeyId, aliceSignedPreKey.getPublicKey(),
                aliceSignature, aliceStore.getIdentityKeyPair().getPublicKey());

        aliceStore.storeSignedPreKey(aliceSignedPreKeyId, new SignedPreKeyRecord(aliceSignedPreKeyId, System.currentTimeMillis(), aliceSignedPreKey, aliceSignature));
        aliceStore.storePreKey(aliceUnsignedPreKeyId, new PreKeyRecord(aliceUnsignedPreKeyId, aliceUnsignedPreKey));

        return alicePreKeyBundle;
    }

    static PreKeyBundle createBobPreKeyBundle(SignalProtocolStore bobStore) throws InvalidKeyException {
        ECKeyPair bobUnsignedPreKey   = Curve.generateKeyPair();
        int       bobUnsignedPreKeyId = new Random().nextInt(Medium.MAX_VALUE);
        byte[]    bobSignature        = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKey.getPublicKey().serialize());

        PreKeyBundle bobPreKeyBundle = new PreKeyBundle(1, 1,
                bobUnsignedPreKeyId, bobUnsignedPreKey.getPublicKey(),
                bobSignedPreKeyId, bobSignedPreKey.getPublicKey(),
                bobSignature, bobStore.getIdentityKeyPair().getPublicKey());

        bobStore.storeSignedPreKey(bobSignedPreKeyId, new SignedPreKeyRecord(bobSignedPreKeyId, System.currentTimeMillis(), bobSignedPreKey, bobSignature));
        bobStore.storePreKey(bobUnsignedPreKeyId, new PreKeyRecord(bobUnsignedPreKeyId, bobUnsignedPreKey));

        return bobPreKeyBundle;
    }

    static SignedPreKeyRecord getSignedPreKey (IdentityKeyPair identityKeyPair) {
        KeyHelper.generateSignedPreKey(identityKeyPair, 5)
    }


    InMemoryIdentityKeyStore inMemoryIdentityKeyStore(IdentityKeyPair identityKeyPair, Integer registrationId){
        return new InMemoryIdentityKeyStore(identityKeyPair, registrationId);
    }
}
