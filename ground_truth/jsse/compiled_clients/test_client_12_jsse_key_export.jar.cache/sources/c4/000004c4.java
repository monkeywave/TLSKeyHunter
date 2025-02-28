package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.MacDerivationFunction;
import org.bouncycastle.crypto.params.KDFDoublePipelineIterationParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/generators/KDFDoublePipelineIterationBytesGenerator.class */
public class KDFDoublePipelineIterationBytesGenerator implements MacDerivationFunction {
    private static final BigInteger INTEGER_MAX = BigInteger.valueOf(2147483647L);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private final Mac prf;

    /* renamed from: h */
    private final int f405h;
    private byte[] fixedInputData;
    private int maxSizeExcl;
    private byte[] ios;
    private boolean useCounter;
    private int generatedBytes;

    /* renamed from: a */
    private byte[] f406a;

    /* renamed from: k */
    private byte[] f407k;

    public KDFDoublePipelineIterationBytesGenerator(Mac mac) {
        this.prf = mac;
        this.f405h = mac.getMacSize();
        this.f406a = new byte[this.f405h];
        this.f407k = new byte[this.f405h];
    }

    @Override // org.bouncycastle.crypto.DerivationFunction
    public void init(DerivationParameters derivationParameters) {
        if (!(derivationParameters instanceof KDFDoublePipelineIterationParameters)) {
            throw new IllegalArgumentException("Wrong type of arguments given");
        }
        KDFDoublePipelineIterationParameters kDFDoublePipelineIterationParameters = (KDFDoublePipelineIterationParameters) derivationParameters;
        this.prf.init(new KeyParameter(kDFDoublePipelineIterationParameters.getKI()));
        this.fixedInputData = kDFDoublePipelineIterationParameters.getFixedInputData();
        int r = kDFDoublePipelineIterationParameters.getR();
        this.ios = new byte[r / 8];
        if (kDFDoublePipelineIterationParameters.useCounter()) {
            BigInteger multiply = TWO.pow(r).multiply(BigInteger.valueOf(this.f405h));
            this.maxSizeExcl = multiply.compareTo(INTEGER_MAX) == 1 ? Integer.MAX_VALUE : multiply.intValue();
        } else {
            this.maxSizeExcl = Integer.MAX_VALUE;
        }
        this.useCounter = kDFDoublePipelineIterationParameters.useCounter();
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
        if (this.generatedBytes % this.f405h == 0) {
            generateNext();
        }
        int i4 = i2;
        int i5 = this.generatedBytes % this.f405h;
        int min = Math.min(this.f405h - (this.generatedBytes % this.f405h), i4);
        System.arraycopy(this.f407k, i5, bArr, i, min);
        this.generatedBytes += min;
        while (true) {
            i4 -= min;
            i += min;
            if (i4 <= 0) {
                return i2;
            }
            generateNext();
            min = Math.min(this.f405h, i4);
            System.arraycopy(this.f407k, 0, bArr, i, min);
            this.generatedBytes += min;
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    private void generateNext() {
        if (this.generatedBytes == 0) {
            this.prf.update(this.fixedInputData, 0, this.fixedInputData.length);
            this.prf.doFinal(this.f406a, 0);
        } else {
            this.prf.update(this.f406a, 0, this.f406a.length);
            this.prf.doFinal(this.f406a, 0);
        }
        this.prf.update(this.f406a, 0, this.f406a.length);
        if (this.useCounter) {
            int i = (this.generatedBytes / this.f405h) + 1;
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
            this.prf.update(this.ios, 0, this.ios.length);
        }
        this.prf.update(this.fixedInputData, 0, this.fixedInputData.length);
        this.prf.doFinal(this.f407k, 0);
    }
}