package org.bouncycastle.pqc.jcajce.provider.lms;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;

/* loaded from: classes2.dex */
class DigestUtil {
    DigestUtil() {
    }

    public static byte[] getDigestResult(Digest digest) {
        int digestSize = digest.getDigestSize();
        byte[] bArr = new byte[digestSize];
        if (digest instanceof Xof) {
            ((Xof) digest).doFinal(bArr, 0, digestSize);
        } else {
            digest.doFinal(bArr, 0);
        }
        return bArr;
    }
}