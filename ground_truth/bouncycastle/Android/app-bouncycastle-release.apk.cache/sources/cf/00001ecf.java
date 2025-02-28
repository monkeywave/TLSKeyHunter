package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/* loaded from: classes2.dex */
public class HMacDSAKCalculator implements DSAKCalculator {

    /* renamed from: K */
    private final byte[] f901K;

    /* renamed from: V */
    private final byte[] f902V;
    private final HMac hMac;

    /* renamed from: n */
    private BigInteger f903n;

    public HMacDSAKCalculator(Digest digest) {
        HMac hMac = new HMac(digest);
        this.hMac = hMac;
        int macSize = hMac.getMacSize();
        this.f902V = new byte[macSize];
        this.f901K = new byte[macSize];
    }

    private BigInteger bitsToInt(byte[] bArr) {
        int length = bArr.length * 8;
        int bitLength = this.f903n.bitLength();
        BigInteger fromUnsignedByteArray = BigIntegers.fromUnsignedByteArray(bArr);
        return length > bitLength ? fromUnsignedByteArray.shiftRight(length - bitLength) : fromUnsignedByteArray;
    }

    @Override // org.bouncycastle.crypto.signers.DSAKCalculator
    public void init(BigInteger bigInteger, BigInteger bigInteger2, byte[] bArr) {
        this.f903n = bigInteger;
        BigInteger bitsToInt = bitsToInt(bArr);
        if (bitsToInt.compareTo(bigInteger) >= 0) {
            bitsToInt = bitsToInt.subtract(bigInteger);
        }
        int unsignedByteLength = BigIntegers.getUnsignedByteLength(bigInteger);
        byte[] asUnsignedByteArray = BigIntegers.asUnsignedByteArray(unsignedByteLength, bigInteger2);
        byte[] asUnsignedByteArray2 = BigIntegers.asUnsignedByteArray(unsignedByteLength, bitsToInt);
        Arrays.fill(this.f901K, (byte) 0);
        Arrays.fill(this.f902V, (byte) 1);
        this.hMac.init(new KeyParameter(this.f901K));
        HMac hMac = this.hMac;
        byte[] bArr2 = this.f902V;
        hMac.update(bArr2, 0, bArr2.length);
        this.hMac.update((byte) 0);
        this.hMac.update(asUnsignedByteArray, 0, asUnsignedByteArray.length);
        this.hMac.update(asUnsignedByteArray2, 0, asUnsignedByteArray2.length);
        initAdditionalInput0(this.hMac);
        this.hMac.doFinal(this.f901K, 0);
        this.hMac.init(new KeyParameter(this.f901K));
        HMac hMac2 = this.hMac;
        byte[] bArr3 = this.f902V;
        hMac2.update(bArr3, 0, bArr3.length);
        this.hMac.doFinal(this.f902V, 0);
        HMac hMac3 = this.hMac;
        byte[] bArr4 = this.f902V;
        hMac3.update(bArr4, 0, bArr4.length);
        this.hMac.update((byte) 1);
        this.hMac.update(asUnsignedByteArray, 0, asUnsignedByteArray.length);
        this.hMac.update(asUnsignedByteArray2, 0, asUnsignedByteArray2.length);
        initAdditionalInput1(this.hMac);
        this.hMac.doFinal(this.f901K, 0);
        this.hMac.init(new KeyParameter(this.f901K));
        HMac hMac4 = this.hMac;
        byte[] bArr5 = this.f902V;
        hMac4.update(bArr5, 0, bArr5.length);
        this.hMac.doFinal(this.f902V, 0);
    }

    @Override // org.bouncycastle.crypto.signers.DSAKCalculator
    public void init(BigInteger bigInteger, SecureRandom secureRandom) {
        throw new IllegalStateException("Operation not supported");
    }

    protected void initAdditionalInput0(HMac hMac) {
    }

    protected void initAdditionalInput1(HMac hMac) {
    }

    @Override // org.bouncycastle.crypto.signers.DSAKCalculator
    public boolean isDeterministic() {
        return true;
    }

    @Override // org.bouncycastle.crypto.signers.DSAKCalculator
    public BigInteger nextK() {
        int unsignedByteLength = BigIntegers.getUnsignedByteLength(this.f903n);
        byte[] bArr = new byte[unsignedByteLength];
        while (true) {
            int i = 0;
            while (i < unsignedByteLength) {
                HMac hMac = this.hMac;
                byte[] bArr2 = this.f902V;
                hMac.update(bArr2, 0, bArr2.length);
                this.hMac.doFinal(this.f902V, 0);
                int min = Math.min(unsignedByteLength - i, this.f902V.length);
                System.arraycopy(this.f902V, 0, bArr, i, min);
                i += min;
            }
            BigInteger bitsToInt = bitsToInt(bArr);
            if (bitsToInt.signum() > 0 && bitsToInt.compareTo(this.f903n) < 0) {
                return bitsToInt;
            }
            HMac hMac2 = this.hMac;
            byte[] bArr3 = this.f902V;
            hMac2.update(bArr3, 0, bArr3.length);
            this.hMac.update((byte) 0);
            this.hMac.doFinal(this.f901K, 0);
            this.hMac.init(new KeyParameter(this.f901K));
            HMac hMac3 = this.hMac;
            byte[] bArr4 = this.f902V;
            hMac3.update(bArr4, 0, bArr4.length);
            this.hMac.doFinal(this.f902V, 0);
        }
    }
}