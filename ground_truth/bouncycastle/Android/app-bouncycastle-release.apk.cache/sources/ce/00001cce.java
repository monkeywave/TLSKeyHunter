package org.bouncycastle.crypto.digests;

import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.MemoableResetException;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class SHA512tDigest extends LongDigest {
    private long H1t;
    private long H2t;
    private long H3t;
    private long H4t;
    private long H5t;
    private long H6t;
    private long H7t;
    private long H8t;
    private int digestLength;

    public SHA512tDigest(int i) {
        this(i, CryptoServicePurpose.ANY);
    }

    public SHA512tDigest(int i, CryptoServicePurpose cryptoServicePurpose) {
        if (i >= 512) {
            throw new IllegalArgumentException("bitLength cannot be >= 512");
        }
        if (i % 8 != 0) {
            throw new IllegalArgumentException("bitLength needs to be a multiple of 8");
        }
        if (i == 384) {
            throw new IllegalArgumentException("bitLength cannot be 384 use SHA384 instead");
        }
        this.digestLength = i / 8;
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
        tIvGenerate(this.digestLength * 8);
        reset();
    }

    public SHA512tDigest(SHA512tDigest sHA512tDigest) {
        super(sHA512tDigest);
        this.digestLength = sHA512tDigest.digestLength;
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
        reset(sHA512tDigest);
    }

    public SHA512tDigest(byte[] bArr) {
        this(readDigestLength(bArr), CryptoServicePurpose.values()[bArr[bArr.length - 1]]);
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
        restoreState(bArr);
    }

    private static void intToBigEndian(int i, byte[] bArr, int i2, int i3) {
        int min = Math.min(4, i3);
        while (true) {
            min--;
            if (min < 0) {
                return;
            }
            bArr[i2 + min] = (byte) (i >>> ((3 - min) * 8));
        }
    }

    private static void longToBigEndian(long j, byte[] bArr, int i, int i2) {
        if (i2 > 0) {
            intToBigEndian((int) (j >>> 32), bArr, i, i2);
            if (i2 > 4) {
                intToBigEndian((int) (j & BodyPartID.bodyIdMax), bArr, i + 4, i2 - 4);
            }
        }
    }

    private static int readDigestLength(byte[] bArr) {
        return Pack.bigEndianToInt(bArr, bArr.length - 5);
    }

    /* JADX WARN: Code restructure failed: missing block: B:7:0x007f, code lost:
        if (r4 > 10) goto L4;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private void tIvGenerate(int r4) {
        /*
            r3 = this;
            r0 = -3482333909917012819(0xcfac43c256196cad, double:-6.392239886847908E75)
            r3.f437H1 = r0
            r0 = 2216346199247487646(0x1ec20b20216f029e, double:1.604250256667292E-160)
            r3.f438H2 = r0
            r0 = -7364697282686394994(0x99cb56d75b315d8e, double:-2.0106609494103695E-184)
            r3.f439H3 = r0
            r0 = 65953792586715988(0xea509ffab89354, double:2.9978976005667514E-304)
            r3.f440H4 = r0
            r0 = -816286391624063116(0xf4abf7da08432774, double:-1.0252515228978657E254)
            r3.f441H5 = r0
            r0 = 4512832404995164602(0x3ea0cd298e9bc9ba, double:5.007211971427005E-7)
            r3.f442H6 = r0
            r0 = -5033199132376557362(0xba267c0e5ee418ce, double:-1.418977391716189E-28)
            r3.f443H7 = r0
            r0 = -124578254951840548(0xfe4568bcb6db84dc, double:-1.7921927020935902E300)
            r3.f444H8 = r0
            r0 = 83
            r3.update(r0)
            r0 = 72
            r3.update(r0)
            r0 = 65
            r3.update(r0)
            r0 = 45
            r3.update(r0)
            r0 = 53
            r3.update(r0)
            r0 = 49
            r3.update(r0)
            r0 = 50
            r3.update(r0)
            r0 = 47
            r3.update(r0)
            r0 = 10
            r1 = 100
            if (r4 <= r1) goto L7f
            int r2 = r4 / 100
            int r2 = r2 + 48
            byte r2 = (byte) r2
            r3.update(r2)
            int r4 = r4 % r1
        L6f:
            int r1 = r4 / 10
            int r1 = r1 + 48
            byte r1 = (byte) r1
            r3.update(r1)
            int r4 = r4 % r0
        L78:
            int r4 = r4 + 48
            byte r4 = (byte) r4
            r3.update(r4)
            goto L82
        L7f:
            if (r4 <= r0) goto L78
            goto L6f
        L82:
            r3.finish()
            long r0 = r3.f437H1
            r3.H1t = r0
            long r0 = r3.f438H2
            r3.H2t = r0
            long r0 = r3.f439H3
            r3.H3t = r0
            long r0 = r3.f440H4
            r3.H4t = r0
            long r0 = r3.f441H5
            r3.H5t = r0
            long r0 = r3.f442H6
            r3.H6t = r0
            long r0 = r3.f443H7
            r3.H7t = r0
            long r0 = r3.f444H8
            r3.H8t = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.crypto.digests.SHA512tDigest.tIvGenerate(int):void");
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new SHA512tDigest(this);
    }

    @Override // org.bouncycastle.crypto.digests.LongDigest
    protected CryptoServiceProperties cryptoServiceProperties() {
        return Utils.getDefaultProperties(this, getDigestSize() * 8, this.purpose);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        longToBigEndian(this.f437H1, bArr, i, this.digestLength);
        longToBigEndian(this.f438H2, bArr, i + 8, this.digestLength - 8);
        longToBigEndian(this.f439H3, bArr, i + 16, this.digestLength - 16);
        longToBigEndian(this.f440H4, bArr, i + 24, this.digestLength - 24);
        longToBigEndian(this.f441H5, bArr, i + 32, this.digestLength - 32);
        longToBigEndian(this.f442H6, bArr, i + 40, this.digestLength - 40);
        longToBigEndian(this.f443H7, bArr, i + 48, this.digestLength - 48);
        longToBigEndian(this.f444H8, bArr, i + 56, this.digestLength - 56);
        reset();
        return this.digestLength;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "SHA-512/" + Integer.toString(this.digestLength * 8);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return this.digestLength;
    }

    @Override // org.bouncycastle.crypto.digests.EncodableDigest
    public byte[] getEncodedState() {
        int encodedStateSize = getEncodedStateSize();
        byte[] bArr = new byte[encodedStateSize + 5];
        populateState(bArr);
        Pack.intToBigEndian(this.digestLength * 8, bArr, encodedStateSize);
        bArr[encodedStateSize + 4] = (byte) this.purpose.ordinal();
        return bArr;
    }

    @Override // org.bouncycastle.crypto.digests.LongDigest, org.bouncycastle.crypto.Digest
    public void reset() {
        super.reset();
        this.f437H1 = this.H1t;
        this.f438H2 = this.H2t;
        this.f439H3 = this.H3t;
        this.f440H4 = this.H4t;
        this.f441H5 = this.H5t;
        this.f442H6 = this.H6t;
        this.f443H7 = this.H7t;
        this.f444H8 = this.H8t;
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        SHA512tDigest sHA512tDigest = (SHA512tDigest) memoable;
        if (this.digestLength != sHA512tDigest.digestLength) {
            throw new MemoableResetException("digestLength inappropriate in other");
        }
        super.copyIn(sHA512tDigest);
        this.H1t = sHA512tDigest.H1t;
        this.H2t = sHA512tDigest.H2t;
        this.H3t = sHA512tDigest.H3t;
        this.H4t = sHA512tDigest.H4t;
        this.H5t = sHA512tDigest.H5t;
        this.H6t = sHA512tDigest.H6t;
        this.H7t = sHA512tDigest.H7t;
        this.H8t = sHA512tDigest.H8t;
    }
}