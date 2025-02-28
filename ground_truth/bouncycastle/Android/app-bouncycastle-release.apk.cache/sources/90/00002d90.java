package org.bouncycastle.tls;

import java.io.IOException;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;

/* loaded from: classes2.dex */
public interface TlsCredentialedAgreement extends TlsCredentials {
    TlsSecret generateAgreement(TlsCertificate tlsCertificate) throws IOException;
}