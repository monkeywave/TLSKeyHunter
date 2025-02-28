package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.MacDerivationFunction;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/generators/KDFCounterBytesGenerator.class */
public class KDFCounterBytesGenerator implements MacDerivationFunction {
    private static final BigInteger INTEGER_MAX = BigInteger.valueOf(2147483647L);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private final Mac prf;

    /* renamed from: h */
    private final int f403h;
    private byte[] fixedInputDataCtrPrefix;
    private byte[] fixedInputData_afterCtr;
    private int maxSizeExcl;
    private byte[] ios;
    private int generatedBytes;

    /* renamed from: k */
    private byte[] f404k;

    public KDFCounterBytesGenerator(Mac mac) {
        this.prf = mac;
        this.f403h = mac.getMacSize();
        this.f404k = new byte[this.f403h];
    }

    @Override // org.bouncycastle.crypto.DerivationFunction
    public void init(DerivationParameters derivationParameters) {
        if (!(derivationParameters instanceof KDFCounterParameters)) {
            throw new IllegalArgumentException("Wrong type of arguments given");
        }
        KDFCounterParameters kDFCounterParameters = (KDFCounterParameters) derivationParameters;
        this.prf.init(new KeyParameter(kDFCounterParameters.getKI()));
        this.fixedInputDataCtrPrefix = kDFCounterParameters.getFixedInputDataCounterPrefix();
        this.fixedInputData_afterCtr = kDFCounterParameters.getFixedInputDataCounterSuffix();
        int r = kDFCounterParameters.getR();
        this.ios = new byte[r / 8];
        BigInteger multiply = TWO.pow(r).multiply(BigInteger.valueOf(this.f403h));
        this.maxSizeExcl = multiply.compareTo(INTEGER_MAX) == 1 ? Integer.MAX_VALUE : multiply.intValue();
        this.generatedBytes = 0;
    }

    @Override // org.bouncycastle.crypto.MacDerivationFunction
    public Mac getMac() {
        return this.prf;
    }

    @Override // org.bouncycastle.crypto.DerivationFunction
    public int generateBytes(byte[] bArr, int i, int i2) throws DataLengthException, IllegalArgumentException {
        int i3 = this.generatedBytes + i2;
        if (i3 < 0 || i3 >= this.maxSizeExcl) {
            throw new DataLengthException("Current KDFCTR may only be used for " + this.maxSizeExcl + " bytes");
        }
        if (this.generatedBytes % this.f403h == 0) {
            generateNext();
        }
        int i4 = i2;
        int i5 = this.generatedBytes % this.f403h;
        int min = Math.min(this.f403h - (this.generatedBytes % this.f403h), i4);
        System.arraycopy(this.f404k, i5, bArr, i, min);
        this.generatedBytes += min;
        while (true) {
            i4 -= min;
            i += min;
            if (i4 <= 0) {
                return i2;
            }
            generateNext();
            min = Math.min(this.f403h, i4);
            System.arraycopy(this.f404k, 0, bArr, i, min);
            this.generatedBytes += min;
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    private void generateNext() {
        int i = (this.generatedBytes / this.f403h) + 1;
        switch (this.ios.length) {
            case 1:
                break;
            case 2:
                this.ios[this.ios.length - 2] = (byte) (i >>> 8);
                break;
            case 3:
                this.ios[this.ios.length - 3] = (byte) (i >>> 16);
                this.ios[this.ios.length - 2] = (byte) (i >>> 8);
                break;
            case 4:
                this.ios[0] = (byte) (i >>> 24);
                this.ios[this.ios.length - 3] = (byte) (i >>> 16);
                this.ios[this.ios.length - 2] = (byte) (i >>> 8);
                break;
            default:
                throw new IllegalStateException("Unsupported size of counter i");
        }
        this.ios[this.ios.length - 1] = (byte) i;
        this.prf.update(this.fixedInputDataCtrPrefix, 0, this.fixedInputDataCtrPrefix.length);
        this.prf.update(this.ios, 0, this.ios.length);
        this.prf.update(this.fixedInputData_afterCtr, 0, this.fixedInputData_afterCtr.length);
        this.prf.doFinal(this.f404k, 0);
    }
}