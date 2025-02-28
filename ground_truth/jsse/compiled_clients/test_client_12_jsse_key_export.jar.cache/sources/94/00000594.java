package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/TweakableBlockCipherParameters.class */
public class TweakableBlockCipherParameters implements CipherParameters {
    private final byte[] tweak;
    private final KeyParameter key;

    public TweakableBlockCipherParameters(KeyParameter keyParameter, byte[] bArr) {
        this.key = keyParameter;
        this.tweak = Arrays.clone(bArr);
    }

    public KeyParameter getKey() {
        return this.key;
    }

    public byte[] getTweak() {
        return this.tweak;
    }
}