package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;

/* loaded from: classes2.dex */
public abstract class JcaTlsDSSVerifier implements TlsVerifier {
    protected final String algorithmName;
    protected final short algorithmType;
    protected final JcaTlsCrypto crypto;
    protected final PublicKey publicKey;

    /* JADX INFO: Access modifiers changed from: protected */
    public JcaTlsDSSVerifier(JcaTlsCrypto jcaTlsCrypto, PublicKey publicKey, short s, String str) {
        if (jcaTlsCrypto == null) {
            throw new NullPointerException("crypto");
        }
        if (publicKey == null) {
            throw new NullPointerException("publicKey");
        }
        this.crypto = jcaTlsCrypto;
        this.publicKey = publicKey;
        this.algorithmType = s;
        this.algorithmName = str;
    }

    @Override // org.bouncycastle.tls.crypto.TlsVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned digitallySigned) throws IOException {
        return null;
    }

    @Override // org.bouncycastle.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] bArr) {
        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();
        if (algorithm == null || algorithm.getSignature() == this.algorithmType) {
            try {
                Signature createSignature = this.crypto.getHelper().createSignature(this.algorithmName);
                createSignature.initVerify(this.publicKey);
                if (algorithm == null) {
                    createSignature.update(bArr, 16, 20);
                } else {
                    createSignature.update(bArr, 0, bArr.length);
                }
                return createSignature.verify(digitallySigned.getSignature());
            } catch (GeneralSecurityException e) {
                throw Exceptions.illegalStateException("unable to process signature: " + e.getMessage(), e);
            }
        }
        throw new IllegalStateException("Invalid algorithm: " + algorithm);
    }
}