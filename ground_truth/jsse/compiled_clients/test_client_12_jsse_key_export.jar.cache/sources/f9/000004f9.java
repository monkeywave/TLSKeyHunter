package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/AEADBlockCipher.class */
public interface AEADBlockCipher extends AEADCipher {
    BlockCipher getUnderlyingCipher();
}