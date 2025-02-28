package org.bouncycastle.crypto.p004ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.p010ec.ECConstants;
import org.bouncycastle.util.BigIntegers;

/* renamed from: org.bouncycastle.crypto.ec.ECUtil */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/ec/ECUtil.class */
class ECUtil {
    ECUtil() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static BigInteger generateK(BigInteger bigInteger, SecureRandom secureRandom) {
        int bitLength = bigInteger.bitLength();
        while (true) {
            BigInteger createRandomBigInteger = BigIntegers.createRandomBigInteger(bitLength, secureRandom);
            if (!createRandomBigInteger.equals(ECConstants.ZERO) && createRandomBigInteger.compareTo(bigInteger) < 0) {
                return createRandomBigInteger;
            }
        }
    }
}