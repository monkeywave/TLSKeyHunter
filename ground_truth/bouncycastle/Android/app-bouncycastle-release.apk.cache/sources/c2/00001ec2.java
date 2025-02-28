package org.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class Ed25519Signer implements Signer {
    private final Buffer buffer = new Buffer();
    private boolean forSigning;
    private Ed25519PrivateKeyParameters privateKey;
    private Ed25519PublicKeyParameters publicKey;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public static final class Buffer extends ByteArrayOutputStream {
        private Buffer() {
        }

        synchronized byte[] generateSignature(Ed25519PrivateKeyParameters ed25519PrivateKeyParameters) {
            byte[] bArr;
            bArr = new byte[64];
            ed25519PrivateKeyParameters.sign(0, null, this.buf, 0, this.count, bArr, 0);
            reset();
            return bArr;
        }

        @Override // java.io.ByteArrayOutputStream
        public synchronized void reset() {
            Arrays.fill(this.buf, 0, this.count, (byte) 0);
            this.count = 0;
        }

        synchronized boolean verifySignature(Ed25519PublicKeyParameters ed25519PublicKeyParameters, byte[] bArr) {
            if (64 != bArr.length) {
                reset();
                return false;
            }
            boolean verify = ed25519PublicKeyParameters.verify(0, null, this.buf, 0, this.count, bArr, 0);
            reset();
            return verify;
        }
    }

    @Override // org.bouncycastle.crypto.Signer
    public byte[] generateSignature() {
        Ed25519PrivateKeyParameters ed25519PrivateKeyParameters;
        if (!this.forSigning || (ed25519PrivateKeyParameters = this.privateKey) == null) {
            throw new IllegalStateException("Ed25519Signer not initialised for signature generation.");
        }
        return this.buffer.generateSignature(ed25519PrivateKeyParameters);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void init(boolean z, CipherParameters cipherParameters) {
        this.forSigning = z;
        if (cipherParameters instanceof ParametersWithRandom) {
            cipherParameters = ((ParametersWithRandom) cipherParameters).getParameters();
        }
        Ed25519PublicKeyParameters ed25519PublicKeyParameters = null;
        if (z) {
            this.privateKey = (Ed25519PrivateKeyParameters) cipherParameters;
        } else {
            this.privateKey = null;
            ed25519PublicKeyParameters = (Ed25519PublicKeyParameters) cipherParameters;
        }
        this.publicKey = ed25519PublicKeyParameters;
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(EdDSAParameterSpec.Ed25519, 128, cipherParameters, z));
        reset();
    }

    @Override // org.bouncycastle.crypto.Signer
    public void reset() {
        this.buffer.reset();
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
    public boolean verifySignature(byte[] bArr) {
        Ed25519PublicKeyParameters ed25519PublicKeyParameters;
        if (this.forSigning || (ed25519PublicKeyParameters = this.publicKey) == null) {
            throw new IllegalStateException("Ed25519Signer not initialised for verification");
        }
        return this.buffer.verifySignature(ed25519PublicKeyParameters, bArr);
    }
}