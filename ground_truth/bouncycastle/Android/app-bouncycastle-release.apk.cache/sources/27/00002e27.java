package org.bouncycastle.tls.crypto.impl.p018bc;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsSigner */
/* loaded from: classes2.dex */
public abstract class BcTlsSigner implements TlsSigner {
    protected final BcTlsCrypto crypto;
    protected final AsymmetricKeyParameter privateKey;

    /* JADX INFO: Access modifiers changed from: protected */
    public BcTlsSigner(BcTlsCrypto bcTlsCrypto, AsymmetricKeyParameter asymmetricKeyParameter) {
        if (bcTlsCrypto == null) {
            throw new NullPointerException("'crypto' cannot be null");
        }
        if (asymmetricKeyParameter == null) {
            throw new NullPointerException("'privateKey' cannot be null");
        }
        if (!asymmetricKeyParameter.isPrivate()) {
            throw new IllegalArgumentException("'privateKey' must be private");
        }
        this.crypto = bcTlsCrypto;
        this.privateKey = asymmetricKeyParameter;
    }

    @Override // org.bouncycastle.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        return null;
    }
}