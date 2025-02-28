package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/* loaded from: classes2.dex */
public class RainbowKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private RainbowKeyComputation rkc;
    private Version version;

    /* renamed from: org.bouncycastle.pqc.crypto.rainbow.RainbowKeyPairGenerator$1 */
    /* loaded from: classes2.dex */
    static /* synthetic */ class C13971 {
        static final /* synthetic */ int[] $SwitchMap$org$bouncycastle$pqc$crypto$rainbow$Version;

        static {
            int[] iArr = new int[Version.values().length];
            $SwitchMap$org$bouncycastle$pqc$crypto$rainbow$Version = iArr;
            try {
                iArr[Version.CLASSIC.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$org$bouncycastle$pqc$crypto$rainbow$Version[Version.CIRCUMZENITHAL.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$org$bouncycastle$pqc$crypto$rainbow$Version[Version.COMPRESSED.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }

    private void initialize(KeyGenerationParameters keyGenerationParameters) {
        RainbowParameters parameters = ((RainbowKeyGenerationParameters) keyGenerationParameters).getParameters();
        this.rkc = new RainbowKeyComputation(parameters, keyGenerationParameters.getRandom());
        this.version = parameters.getVersion();
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        int i = C13971.$SwitchMap$org$bouncycastle$pqc$crypto$rainbow$Version[this.version.ordinal()];
        if (i != 1) {
            if (i != 2) {
                if (i == 3) {
                    return this.rkc.genKeyPairCompressed();
                }
                throw new IllegalArgumentException("No valid version. Please choose one of the following: classic, circumzenithal, compressed");
            }
            return this.rkc.genKeyPairCircumzenithal();
        }
        return this.rkc.genKeyPairClassical();
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        initialize(keyGenerationParameters);
    }
}