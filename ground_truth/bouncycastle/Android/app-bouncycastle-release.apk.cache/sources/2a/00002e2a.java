package org.bouncycastle.tls.crypto.impl.p018bc;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsVerifier */
/* loaded from: classes2.dex */
public abstract class BcTlsVerifier implements TlsVerifier {
    protected final BcTlsCrypto crypto;
    protected final AsymmetricKeyParameter publicKey;

    /* JADX INFO: Access modifiers changed from: protected */
    public BcTlsVerifier(BcTlsCrypto bcTlsCrypto, AsymmetricKeyParameter asymmetricKeyParameter) {
        if (bcTlsCrypto == null) {
            throw new NullPointerException("'crypto' cannot be null");
        }
        if (asymmetricKeyParameter == null) {
            throw new NullPointerException("'publicKey' cannot be null");
        }
        if (asymmetricKeyParameter.isPrivate()) {
            throw new IllegalArgumentException("'publicKey' must be public");
        }
        this.crypto = bcTlsCrypto;
        this.publicKey = asymmetricKeyParameter;
    }

    @Override // org.bouncycastle.tls.crypto.TlsVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned digitallySigned) {
        return null;
    }
}