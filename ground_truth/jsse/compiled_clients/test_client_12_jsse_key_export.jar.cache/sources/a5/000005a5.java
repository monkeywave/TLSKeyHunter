package org.bouncycastle.crypto.prng;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/prng/EntropyUtil.class */
public class EntropyUtil {
    public static byte[] generateSeed(EntropySource entropySource, int i) {
        byte[] bArr = new byte[i];
        if (i * 8 > entropySource.entropySize()) {
            int entropySize = entropySource.entropySize() / 8;
            int i2 = 0;
            while (true) {
                int i3 = i2;
                if (i3 >= bArr.length) {
                    break;
                }
                byte[] entropy = entropySource.getEntropy();
                if (entropy.length <= bArr.length - i3) {
                    System.arraycopy(entropy, 0, bArr, i3, entropy.length);
                } else {
                    System.arraycopy(entropy, 0, bArr, i3, bArr.length - i3);
                }
                i2 = i3 + entropySize;
            }
        } else {
            System.arraycopy(entropySource.getEntropy(), 0, bArr, 0, bArr.length);
        }
        return bArr;
    }
}