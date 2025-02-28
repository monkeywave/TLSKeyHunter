package org.bouncycastle.tls.crypto;

import java.io.IOException;

/* loaded from: classes2.dex */
public interface TlsAgreement {
    TlsSecret calculateSecret() throws IOException;

    byte[] generateEphemeral() throws IOException;

    void receivePeerValue(byte[] bArr) throws IOException;
}