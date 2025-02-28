package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/signers/HMacDSAKCalculator.class */
public class HMacDSAKCalculator implements DSAKCalculator {
    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private final HMac hMac;

    /* renamed from: K */
    private final byte[] f583K;

    /* renamed from: V */
    private final byte[] f584V;

    /* renamed from: n */
    private BigInteger f585n;

    public HMacDSAKCalculator(Digest digest) {
        this.hMac = new HMac(digest);
        this.f584V = new byte[this.hMac.getMacSize()];
        this.f583K = new byte[this.hMac.getMacSize()];
    }

    @Override // org.bouncycastle.crypto.signers.DSAKCalculator
    public boolean isDeterministic() {
        return true;
    }

    @Override // org.bouncycastle.crypto.signers.DSAKCalculator
    public void init(BigInteger bigInteger, SecureRandom secureRandom) {
        throw new IllegalStateException("Operation not supported");
    }

    @Override // org.bouncycastle.crypto.signers.DSAKCalculator
    public void init(BigInteger bigInteger, BigInteger bigInteger2, byte[] bArr) {
        this.f585n = bigInteger;
        Arrays.fill(this.f584V, (byte) 1);
        Arrays.fill(this.f583K, (byte) 0);
        int unsignedByteLength = BigIntegers.getUnsignedByteLength(bigInteger);
        byte[] bArr2 = new byte[unsignedByteLength];
        byte[] asUnsignedByteArray = BigIntegers.asUnsignedByteArray(bigInteger2);
        System.arraycopy(asUnsignedByteArray, 0, bArr2, bArr2.length - asUnsignedByteArray.length, asUnsignedByteArray.length);
        byte[] bArr3 = new byte[unsignedByteLength];
        BigInteger bitsToInt = bitsToInt(bArr);
        if (bitsToInt.compareTo(bigInteger) >= 0) {
            bitsToInt = bitsToInt.subtract(bigInteger);
        }
        byte[] asUnsignedByteArray2 = BigIntegers.asUnsignedByteArray(bitsToInt);
        System.arraycopy(asUnsignedByteArray2, 0, bArr3, bArr3.length - asUnsignedByteArray2.length, asUnsignedByteArray2.length);
        this.hMac.init(new KeyParameter(this.f583K));
        this.hMac.update(this.f584V, 0, this.f584V.length);
        this.hMac.update((byte) 0);
        this.hMac.update(bArr2, 0, bArr2.length);
        this.hMac.update(bArr3, 0, bArr3.length);
        this.hMac.doFinal(this.f583K, 0);
        this.hMac.init(new KeyParameter(this.f583K));
        this.hMac.update(this.f584V, 0, this.f584V.length);
        this.hMac.doFinal(this.f584V, 0);
        this.hMac.update(this.f584V, 0, this.f584V.length);
        this.hMac.update((byte) 1);
        this.hMac.update(bArr2, 0, bArr2.length);
        this.hMac.update(bArr3, 0, bArr3.length);
        this.hMac.doFinal(this.f583K, 0);
        this.hMac.init(new KeyParameter(this.f583K));
        this.hMac.update(this.f584V, 0, this.f584V.length);
        this.hMac.doFinal(this.f584V, 0);
    }

    @Override // org.bouncycastle.crypto.signers.DSAKCalculator
    public BigInteger nextK() {
        byte[] bArr = new byte[BigIntegers.getUnsignedByteLength(this.f585n)];
        while (true) {
            int i = 0;
            while (true) {
                int i2 = i;
                if (i2 >= bArr.length) {
                    break;
                }
                this.hMac.update(this.f584V, 0, this.f584V.length);
                this.hMac.doFinal(this.f584V, 0);
                int min = Math.min(bArr.length - i2, this.f584V.length);
                System.arraycopy(this.f584V, 0, bArr, i2, min);
                i = i2 + min;
            }
            BigInteger bitsToInt = bitsToInt(bArr);
            if (bitsToInt.compareTo(ZERO) > 0 && bitsToInt.compareTo(this.f585n) < 0) {
                return bitsToInt;
            }
            this.hMac.update(this.f584V, 0, this.f584V.length);
            this.hMac.update((byte) 0);
            this.hMac.doFinal(this.f583K, 0);
            this.hMac.init(new KeyParameter(this.f583K));
            this.hMac.update(this.f584V, 0, this.f584V.length);
            this.hMac.doFinal(this.f584V, 0);
        }
    }

    private BigInteger bitsToInt(byte[] bArr) {
        BigInteger bigInteger = new BigInteger(1, bArr);
        if (bArr.length * 8 > this.f585n.bitLength()) {
            bigInteger = bigInteger.shiftRight((bArr.length * 8) - this.f585n.bitLength());
        }
        return bigInteger;
    }
}