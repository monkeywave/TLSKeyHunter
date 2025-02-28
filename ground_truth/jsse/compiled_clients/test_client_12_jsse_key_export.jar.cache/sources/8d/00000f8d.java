package org.openjsse.sun.security.provider;

import java.security.ProviderException;
import java.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/provider/SHA3.class */
abstract class SHA3 extends DigestBase {
    private static final int WIDTH = 200;

    /* renamed from: DM */
    private static final int f956DM = 5;

    /* renamed from: NR */
    private static final int f957NR = 24;
    private static final long[] RC_CONSTANTS = {1, 32898, -9223372036854742902L, -9223372034707259392L, 32907, 2147483649L, -9223372034707259263L, -9223372036854743031L, 138, 136, 2147516425L, 2147483658L, 2147516555L, -9223372036854775669L, -9223372036854742903L, -9223372036854743037L, -9223372036854743038L, -9223372036854775680L, 32778, -9223372034707292150L, -9223372034707259263L, -9223372036854742912L, 2147483649L, -9223372034707259384L};
    private byte[] state;
    private long[] lanes;

    SHA3(String name, int digestLength) {
        super(name, digestLength, 200 - (2 * digestLength));
        this.state = new byte[200];
        this.lanes = new long[25];
    }

    @Override // org.openjsse.sun.security.provider.DigestBase
    void implCompress(byte[] b, int ofs) {
        for (int i = 0; i < this.buffer.length; i++) {
            byte[] bArr = this.state;
            int i2 = i;
            int i3 = ofs;
            ofs++;
            bArr[i2] = (byte) (bArr[i2] ^ b[i3]);
        }
        keccak();
    }

    @Override // org.openjsse.sun.security.provider.DigestBase
    void implDigest(byte[] out, int ofs) {
        int numOfPadding = setPaddingBytes(this.buffer, (int) (this.bytesProcessed % this.buffer.length));
        if (numOfPadding < 1) {
            throw new ProviderException("Incorrect pad size: " + numOfPadding);
        }
        for (int i = 0; i < this.buffer.length; i++) {
            byte[] bArr = this.state;
            int i2 = i;
            bArr[i2] = (byte) (bArr[i2] ^ this.buffer[i]);
        }
        keccak();
        System.arraycopy(this.state, 0, out, ofs, engineGetDigestLength());
    }

    @Override // org.openjsse.sun.security.provider.DigestBase
    void implReset() {
        Arrays.fill(this.state, (byte) 0);
        Arrays.fill(this.lanes, 0L);
    }

    private static int setPaddingBytes(byte[] in, int len) {
        if (len != in.length) {
            Arrays.fill(in, len, in.length, (byte) 0);
            in[len] = (byte) (in[len] | 6);
            int length = in.length - 1;
            in[length] = (byte) (in[length] | Byte.MIN_VALUE);
        }
        return in.length - len;
    }

    private static void bytes2Lanes(byte[] s, long[] m) {
        int sOfs = 0;
        int y = 0;
        while (y < 5) {
            ByteArrayAccess.b2lLittle(s, sOfs, m, 5 * y, 40);
            y++;
            sOfs += 40;
        }
    }

    private static void lanes2Bytes(long[] m, byte[] s) {
        int sOfs = 0;
        int y = 0;
        while (y < 5) {
            ByteArrayAccess.l2bLittle(m, 5 * y, s, sOfs, 40);
            y++;
            sOfs += 40;
        }
    }

    private static long[] smTheta(long[] a) {
        long c0 = (((a[0] ^ a[5]) ^ a[10]) ^ a[15]) ^ a[20];
        long c1 = (((a[1] ^ a[6]) ^ a[11]) ^ a[16]) ^ a[21];
        long c2 = (((a[2] ^ a[7]) ^ a[12]) ^ a[17]) ^ a[22];
        long c3 = (((a[3] ^ a[8]) ^ a[13]) ^ a[18]) ^ a[23];
        long c4 = (((a[4] ^ a[9]) ^ a[14]) ^ a[19]) ^ a[24];
        long d0 = c4 ^ Long.rotateLeft(c1, 1);
        long d1 = c0 ^ Long.rotateLeft(c2, 1);
        long d2 = c1 ^ Long.rotateLeft(c3, 1);
        long d3 = c2 ^ Long.rotateLeft(c4, 1);
        long d4 = c3 ^ Long.rotateLeft(c0, 1);
        for (int y = 0; y < a.length; y += 5) {
            int i = y;
            a[i] = a[i] ^ d0;
            int i2 = y + 1;
            a[i2] = a[i2] ^ d1;
            int i3 = y + 2;
            a[i3] = a[i3] ^ d2;
            int i4 = y + 3;
            a[i4] = a[i4] ^ d3;
            int i5 = y + 4;
            a[i5] = a[i5] ^ d4;
        }
        return a;
    }

    private static long[] smPiRho(long[] a) {
        long tmp = Long.rotateLeft(a[10], 3);
        a[10] = Long.rotateLeft(a[1], 1);
        a[1] = Long.rotateLeft(a[6], 44);
        a[6] = Long.rotateLeft(a[9], 20);
        a[9] = Long.rotateLeft(a[22], 61);
        a[22] = Long.rotateLeft(a[14], 39);
        a[14] = Long.rotateLeft(a[20], 18);
        a[20] = Long.rotateLeft(a[2], 62);
        a[2] = Long.rotateLeft(a[12], 43);
        a[12] = Long.rotateLeft(a[13], 25);
        a[13] = Long.rotateLeft(a[19], 8);
        a[19] = Long.rotateLeft(a[23], 56);
        a[23] = Long.rotateLeft(a[15], 41);
        a[15] = Long.rotateLeft(a[4], 27);
        a[4] = Long.rotateLeft(a[24], 14);
        a[24] = Long.rotateLeft(a[21], 2);
        a[21] = Long.rotateLeft(a[8], 55);
        a[8] = Long.rotateLeft(a[16], 45);
        a[16] = Long.rotateLeft(a[5], 36);
        a[5] = Long.rotateLeft(a[3], 28);
        a[3] = Long.rotateLeft(a[18], 21);
        a[18] = Long.rotateLeft(a[17], 15);
        a[17] = Long.rotateLeft(a[11], 10);
        a[11] = Long.rotateLeft(a[7], 6);
        a[7] = tmp;
        return a;
    }

    private static long[] smChi(long[] a) {
        for (int y = 0; y < a.length; y += 5) {
            long ay0 = a[y];
            long ay1 = a[y + 1];
            long ay2 = a[y + 2];
            long ay3 = a[y + 3];
            long ay4 = a[y + 4];
            a[y] = ay0 ^ ((ay1 ^ (-1)) & ay2);
            a[y + 1] = ay1 ^ ((ay2 ^ (-1)) & ay3);
            a[y + 2] = ay2 ^ ((ay3 ^ (-1)) & ay4);
            a[y + 3] = ay3 ^ ((ay4 ^ (-1)) & ay0);
            a[y + 4] = ay4 ^ ((ay0 ^ (-1)) & ay1);
        }
        return a;
    }

    private static long[] smIota(long[] a, int rndIndex) {
        a[0] = a[0] ^ RC_CONSTANTS[rndIndex];
        return a;
    }

    private void keccak() {
        bytes2Lanes(this.state, this.lanes);
        for (int ir = 0; ir < 24; ir++) {
            smIota(smChi(smPiRho(smTheta(this.lanes))), ir);
        }
        lanes2Bytes(this.lanes, this.state);
    }

    @Override // org.openjsse.sun.security.provider.DigestBase, java.security.MessageDigestSpi
    public Object clone() throws CloneNotSupportedException {
        SHA3 copy = (SHA3) super.clone();
        copy.state = (byte[]) copy.state.clone();
        copy.lanes = new long[25];
        return copy;
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/provider/SHA3$SHA224.class */
    public static final class SHA224 extends SHA3 {
        @Override // org.openjsse.sun.security.provider.SHA3, org.openjsse.sun.security.provider.DigestBase, java.security.MessageDigestSpi
        public /* bridge */ /* synthetic */ Object clone() throws CloneNotSupportedException {
            return super.clone();
        }

        public SHA224() {
            super("SHA3-224", 28);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/provider/SHA3$SHA256.class */
    public static final class SHA256 extends SHA3 {
        @Override // org.openjsse.sun.security.provider.SHA3, org.openjsse.sun.security.provider.DigestBase, java.security.MessageDigestSpi
        public /* bridge */ /* synthetic */ Object clone() throws CloneNotSupportedException {
            return super.clone();
        }

        public SHA256() {
            super("SHA3-256", 32);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/provider/SHA3$SHA384.class */
    public static final class SHA384 extends SHA3 {
        @Override // org.openjsse.sun.security.provider.SHA3, org.openjsse.sun.security.provider.DigestBase, java.security.MessageDigestSpi
        public /* bridge */ /* synthetic */ Object clone() throws CloneNotSupportedException {
            return super.clone();
        }

        public SHA384() {
            super("SHA3-384", 48);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/provider/SHA3$SHA512.class */
    public static final class SHA512 extends SHA3 {
        @Override // org.openjsse.sun.security.provider.SHA3, org.openjsse.sun.security.provider.DigestBase, java.security.MessageDigestSpi
        public /* bridge */ /* synthetic */ Object clone() throws CloneNotSupportedException {
            return super.clone();
        }

        public SHA512() {
            super("SHA3-512", 64);
        }
    }
}