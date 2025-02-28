package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

/* loaded from: classes2.dex */
public class JcaTlsRSASigner implements TlsSigner {
    private final JcaTlsCrypto crypto;
    private final PrivateKey privateKey;
    private Signature rawSigner;

    public JcaTlsRSASigner(JcaTlsCrypto jcaTlsCrypto, PrivateKey privateKey) {
        this.rawSigner = null;
        if (jcaTlsCrypto == null) {
            throw new NullPointerException("crypto");
        }
        if (privateKey == null) {
            throw new NullPointerException("privateKey");
        }
        this.crypto = jcaTlsCrypto;
        this.privateKey = privateKey;
    }

    public JcaTlsRSASigner(JcaTlsCrypto jcaTlsCrypto, PrivateKey privateKey, PublicKey publicKey) {
        this(jcaTlsCrypto, privateKey);
    }

    @Override // org.bouncycastle.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm signatureAndHashAlgorithm, byte[] bArr) throws IOException {
        try {
            try {
                Signature rawSigner = getRawSigner();
                if (signatureAndHashAlgorithm != null) {
                    if (signatureAndHashAlgorithm.getSignature() != 1) {
                        throw new IllegalStateException("Invalid algorithm: " + signatureAndHashAlgorithm);
                    }
                    bArr = new DigestInfo(new AlgorithmIdentifier(TlsUtils.getOIDForHashAlgorithm(signatureAndHashAlgorithm.getHash()), DERNull.INSTANCE), bArr).getEncoded();
                }
                rawSigner.update(bArr, 0, bArr.length);
                return rawSigner.sign();
            } catch (GeneralSecurityException e) {
                throw new TlsFatalAlert((short) 80, (Throwable) e);
            }
        } finally {
            this.rawSigner = null;
        }
    }

    protected Signature getRawSigner() throws GeneralSecurityException {
        if (this.rawSigner == null) {
            Signature createSignature = this.crypto.getHelper().createSignature("NoneWithRSA");
            this.rawSigner = createSignature;
            createSignature.initSign(this.privateKey, this.crypto.getSecureRandom());
        }
        return this.rawSigner;
    }

    @Override // org.bouncycastle.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws IOException {
        if (signatureAndHashAlgorithm != null && 1 == signatureAndHashAlgorithm.getSignature() && JcaUtils.isSunMSCAPIProviderActive() && isSunMSCAPIRawSigner()) {
            return this.crypto.createStreamSigner(signatureAndHashAlgorithm, this.privateKey, true);
        }
        return null;
    }

    protected boolean isSunMSCAPIRawSigner() throws IOException {
        try {
            return JcaUtils.isSunMSCAPIProvider(getRawSigner().getProvider());
        } catch (GeneralSecurityException unused) {
            return true;
        }
    }
}