package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsDSSSigner */
/* loaded from: classes2.dex */
public abstract class BcTlsDSSSigner extends BcTlsSigner {
    /* JADX INFO: Access modifiers changed from: protected */
    public BcTlsDSSSigner(BcTlsCrypto bcTlsCrypto, AsymmetricKeyParameter asymmetricKeyParameter) {
        super(bcTlsCrypto, asymmetricKeyParameter);
    }

    protected abstract DSA createDSAImpl(int i);

    @Override // org.bouncycastle.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm signatureAndHashAlgorithm, byte[] bArr) throws IOException {
        int i;
        int length;
        if (signatureAndHashAlgorithm == null || signatureAndHashAlgorithm.getSignature() == getSignatureAlgorithm()) {
            DSADigestSigner dSADigestSigner = new DSADigestSigner(createDSAImpl(signatureAndHashAlgorithm == null ? 2 : TlsCryptoUtils.getHash(signatureAndHashAlgorithm.getHash())), new NullDigest());
            dSADigestSigner.init(true, new ParametersWithRandom(this.privateKey, this.crypto.getSecureRandom()));
            if (signatureAndHashAlgorithm == null) {
                i = 16;
                length = 20;
            } else {
                i = 0;
                length = bArr.length;
            }
            dSADigestSigner.update(bArr, i, length);
            try {
                return dSADigestSigner.generateSignature();
            } catch (CryptoException e) {
                throw new TlsFatalAlert((short) 80, (Throwable) e);
            }
        }
        throw new IllegalStateException("Invalid algorithm: " + signatureAndHashAlgorithm);
    }

    protected abstract short getSignatureAlgorithm();
}