package org.bouncycastle.crypto.constraints;

import java.math.BigInteger;
import org.bouncycastle.math.p016ec.ECCurve;

/* loaded from: classes2.dex */
public class ConstraintUtils {
    public static int bitsOfSecurityFor(BigInteger bigInteger) {
        return bitsOfSecurityForFF(bigInteger.bitLength());
    }

    public static int bitsOfSecurityFor(ECCurve eCCurve) {
        int fieldSize = (eCCurve.getFieldSize() + 1) / 2;
        if (fieldSize > 256) {
            return 256;
        }
        return fieldSize;
    }

    public static int bitsOfSecurityForFF(int i) {
        if (i < 2048) {
            return i >= 1024 ? 80 : 20;
        } else if (i >= 3072) {
            if (i >= 7680) {
                return i >= 15360 ? 256 : 192;
            }
            return 128;
        } else {
            return 112;
        }
    }
}