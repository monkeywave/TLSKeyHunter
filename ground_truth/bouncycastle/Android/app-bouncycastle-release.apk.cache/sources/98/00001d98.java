package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.DESedeParameters;

/* loaded from: classes2.dex */
public class DESedeKeyGenerator extends DESKeyGenerator {
    private static final int MAX_IT = 20;

    @Override // org.bouncycastle.crypto.generators.DESKeyGenerator, org.bouncycastle.crypto.CipherKeyGenerator
    public byte[] generateKey() {
        int i = this.strength;
        byte[] bArr = new byte[i];
        int i2 = 0;
        while (true) {
            this.random.nextBytes(bArr);
            DESedeParameters.setOddParity(bArr);
            i2++;
            if (i2 >= 20 || (!DESedeParameters.isWeakKey(bArr, 0, i) && DESedeParameters.isRealEDEKey(bArr, 0))) {
                break;
            }
        }
        if (DESedeParameters.isWeakKey(bArr, 0, i) || !DESedeParameters.isRealEDEKey(bArr, 0)) {
            throw new IllegalStateException("Unable to generate DES-EDE key");
        }
        return bArr;
    }

    @Override // org.bouncycastle.crypto.generators.DESKeyGenerator, org.bouncycastle.crypto.CipherKeyGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.random = keyGenerationParameters.getRandom();
        this.strength = (keyGenerationParameters.getStrength() + 7) / 8;
        if (this.strength == 0 || this.strength == 21) {
            this.strength = 24;
        } else if (this.strength == 14) {
            this.strength = 16;
        } else if (this.strength != 24 && this.strength != 16) {
            throw new IllegalArgumentException("DESede key must be 192 or 128 bits long.");
        }
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("DESedeKeyGen", 112, null, CryptoServicePurpose.KEYGEN));
    }
}