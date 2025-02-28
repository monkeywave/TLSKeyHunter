package org.openjsse.sun.security.ssl;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/EphemeralKeyManager.class */
final class EphemeralKeyManager {
    private static final int INDEX_RSA512 = 0;
    private static final int INDEX_RSA1024 = 1;
    private final EphemeralKeyPair[] keys = {new EphemeralKeyPair(null), new EphemeralKeyPair(null)};

    /* JADX INFO: Access modifiers changed from: package-private */
    public KeyPair getRSAKeyPair(boolean export, SecureRandom random) {
        int length;
        int index;
        KeyPair keyPair;
        if (export) {
            length = 512;
            index = 0;
        } else {
            length = 1024;
            index = 1;
        }
        synchronized (this.keys) {
            KeyPair kp = this.keys[index].getKeyPair();
            if (kp == null) {
                try {
                    KeyPairGenerator kgen = JsseJce.getKeyPairGenerator("RSA");
                    kgen.initialize(length, random);
                    this.keys[index] = new EphemeralKeyPair(kgen.genKeyPair());
                    kp = this.keys[index].getKeyPair();
                } catch (Exception e) {
                }
            }
            keyPair = kp;
        }
        return keyPair;
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/EphemeralKeyManager$EphemeralKeyPair.class */
    private static class EphemeralKeyPair {
        private static final int MAX_USE = 200;
        private static final long USE_INTERVAL = 3600000;
        private KeyPair keyPair;
        private int uses;
        private long expirationTime;

        private EphemeralKeyPair(KeyPair keyPair) {
            this.keyPair = keyPair;
            this.expirationTime = System.currentTimeMillis() + USE_INTERVAL;
        }

        private boolean isValid() {
            return this.keyPair != null && this.uses < 200 && System.currentTimeMillis() < this.expirationTime;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public KeyPair getKeyPair() {
            if (!isValid()) {
                this.keyPair = null;
                return null;
            }
            this.uses++;
            return this.keyPair;
        }
    }
}