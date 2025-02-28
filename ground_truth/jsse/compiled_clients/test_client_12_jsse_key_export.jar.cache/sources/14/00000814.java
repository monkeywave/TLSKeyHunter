package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.io.IOException;
import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/util/DSAEncoder.class */
public interface DSAEncoder {
    byte[] encode(BigInteger bigInteger, BigInteger bigInteger2) throws IOException;

    BigInteger[] decode(byte[] bArr) throws IOException;
}