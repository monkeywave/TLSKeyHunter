package org.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.math.p010ec.rfc8032.Ed25519;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/signers/Ed25519Signer.class */
public class Ed25519Signer implements Signer {
    private final Buffer buffer = new Buffer();
    private boolean forSigning;
    private Ed25519PrivateKeyParameters privateKey;
    private Ed25519PublicKeyParameters publicKey;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/signers/Ed25519Signer$Buffer.class */
    public static class Buffer extends ByteArrayOutputStream {
        private Buffer() {
        }

        synchronized byte[] generateSignature(Ed25519PrivateKeyParameters ed25519PrivateKeyParameters) {
            byte[] bArr = new byte[64];
            ed25519PrivateKeyParameters.sign(0, null, this.buf, 0, this.count, bArr, 0);
            reset();
            return bArr;
        }

        synchronized boolean verifySignature(Ed25519PublicKeyParameters ed25519PublicKeyParameters, byte[] bArr) {
            if (64 != bArr.length) {
                reset();
                return false;
            }
            boolean verify = Ed25519.verify(bArr, 0, ed25519PublicKeyParameters.getEncoded(), 0, this.buf, 0, this.count);
            reset();
            return verify;
        }

        @Override // java.io.ByteArrayOutputStream
        public synchronized void reset() {
            Arrays.fill(this.buf, 0, this.count, (byte) 0);
            this.count = 0;
        }
    }

    @Override // org.bouncycastle.crypto.Signer
    public void init(boolean z, CipherParameters cipherParameters) {
        this.forSigning = z;
        if (z) {
            this.privateKey = (Ed25519PrivateKeyParameters) cipherParameters;
            this.publicKey = null;
        } else {
            this.privateKey = null;
            this.publicKey = (Ed25519PublicKeyParameters) cipherParameters;
        }
        reset();
    }

    @Override // org.bouncycastle.crypto.Signer
    public void update(byte b) {
        this.buffer.write(b);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void update(byte[] bArr, int i, int i2) {
        this.buffer.write(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.Signer
    public byte[] generateSignature() {
        if (!this.forSigning || null == this.privateKey) {
            throw new IllegalStateException("Ed25519Signer not initialised for signature generation.");
        }
        return this.buffer.generateSignature(this.privateKey);
    }

    @Override // org.bouncycastle.crypto.Signer
    public boolean verifySignature(byte[] bArr) {
        if (this.forSigning || null == this.publicKey) {
            throw new IllegalStateException("Ed25519Signer not initialised for verification");
        }
        return this.buffer.verifySignature(this.publicKey, bArr);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void reset() {
        this.buffer.reset();
    }
}