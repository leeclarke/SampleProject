package org.meadowhawk.signal

import org.whispersystems.libsignal.IdentityKey
import org.whispersystems.libsignal.IdentityKeyPair
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;
import org.whispersystems.libsignal.util.KeyHelper;

     class TestInMemorySignalProtocolStore extends InMemorySignalProtocolStore {
         TestInMemorySignalProtocolStore() {
            super(generateIdentityKeyPair(), generateRegistrationId());
        }

        private static IdentityKeyPair generateIdentityKeyPair() {
            ECKeyPair identityKeyPairKeys = Curve.generateKeyPair();

            return new IdentityKeyPair(new IdentityKey(identityKeyPairKeys.getPublicKey()),
                    identityKeyPairKeys.getPrivateKey());
        }

        private static int generateRegistrationId() {
            return KeyHelper.generateRegistrationId(false);
        }
    }
