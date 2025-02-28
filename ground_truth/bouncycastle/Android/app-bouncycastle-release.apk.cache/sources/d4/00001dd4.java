package org.bouncycastle.crypto.kems;

import java.util.concurrent.atomic.AtomicBoolean;
import javax.security.auth.DestroyFailedException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
class SecretWithEncapsulationImpl implements SecretWithEncapsulation {
    private final byte[] cipher_text;
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);
    private final byte[] sessionKey;

    public SecretWithEncapsulationImpl(byte[] bArr, byte[] bArr2) {
        this.sessionKey = bArr;
        this.cipher_text = bArr2;
    }

    void checkDestroyed() {
        if (isDestroyed()) {
            throw new IllegalStateException("data has been destroyed");
        }
    }

    @Override // javax.security.auth.Destroyable
    public void destroy() throws DestroyFailedException {
        if (this.hasBeenDestroyed.getAndSet(true)) {
            return;
        }
        Arrays.clear(this.sessionKey);
        Arrays.clear(this.cipher_text);
    }

    @Override // org.bouncycastle.crypto.SecretWithEncapsulation
    public byte[] getEncapsulation() {
        byte[] clone = Arrays.clone(this.cipher_text);
        checkDestroyed();
        return clone;
    }

    @Override // org.bouncycastle.crypto.SecretWithEncapsulation
    public byte[] getSecret() {
        byte[] clone = Arrays.clone(this.sessionKey);
        checkDestroyed();
        return clone;
    }

    @Override // javax.security.auth.Destroyable
    public boolean isDestroyed() {
        return this.hasBeenDestroyed.get();
    }
}