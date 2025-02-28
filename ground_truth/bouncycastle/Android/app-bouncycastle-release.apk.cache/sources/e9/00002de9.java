package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.math.BigInteger;

/* loaded from: classes2.dex */
public interface TlsSRP6Server {
    BigInteger calculateSecret(BigInteger bigInteger) throws IOException;

    BigInteger generateServerCredentials();
}