package org.bouncycastle.math.p016ec;

import java.math.BigInteger;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.math.p016ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

/* JADX INFO: Access modifiers changed from: package-private */
/* renamed from: org.bouncycastle.math.ec.Tnaf */
/* loaded from: classes2.dex */
public class Tnaf {
    private static final BigInteger MINUS_ONE;
    private static final BigInteger MINUS_THREE;
    private static final BigInteger MINUS_TWO;
    public static final byte WIDTH = 4;
    public static final ZTauElement[] alpha0;
    public static final byte[][] alpha0Tnaf;
    public static final ZTauElement[] alpha1;
    public static final byte[][] alpha1Tnaf;

    static {
        BigInteger negate = ECConstants.ONE.negate();
        MINUS_ONE = negate;
        MINUS_TWO = ECConstants.TWO.negate();
        BigInteger negate2 = ECConstants.THREE.negate();
        MINUS_THREE = negate2;
        alpha0 = new ZTauElement[]{null, new ZTauElement(ECConstants.ONE, ECConstants.ZERO), null, new ZTauElement(negate2, negate), null, new ZTauElement(negate, negate), null, new ZTauElement(ECConstants.ONE, negate), null, new ZTauElement(negate, ECConstants.ONE), null, new ZTauElement(ECConstants.ONE, ECConstants.ONE), null, new ZTauElement(ECConstants.THREE, ECConstants.ONE), null, new ZTauElement(negate, ECConstants.ZERO)};
        alpha0Tnaf = new byte[][]{null, new byte[]{1}, null, new byte[]{-1, 0, 1}, null, new byte[]{1, 0, 1}, null, new byte[]{-1, 0, 0, 1}};
        alpha1 = new ZTauElement[]{null, new ZTauElement(ECConstants.ONE, ECConstants.ZERO), null, new ZTauElement(negate2, ECConstants.ONE), null, new ZTauElement(negate, ECConstants.ONE), null, new ZTauElement(ECConstants.ONE, ECConstants.ONE), null, new ZTauElement(negate, negate), null, new ZTauElement(ECConstants.ONE, negate), null, new ZTauElement(ECConstants.THREE, negate), null, new ZTauElement(negate, ECConstants.ZERO)};
        alpha1Tnaf = new byte[][]{null, new byte[]{1}, null, new byte[]{-1, 0, 1}, null, new byte[]{1, 0, 1}, null, new byte[]{-1, 0, 0, -1}};
    }

    Tnaf() {
    }

    public static SimpleBigDecimal approximateDivisionByN(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, byte b, int i, int i2) {
        int i3 = ((i + 5) / 2) + i2;
        BigInteger multiply = bigInteger2.multiply(bigInteger.shiftRight(((i - i3) - 2) + b));
        BigInteger add = multiply.add(bigInteger3.multiply(multiply.shiftRight(i)));
        int i4 = i3 - i2;
        BigInteger shiftRight = add.shiftRight(i4);
        if (add.testBit(i4 - 1)) {
            shiftRight = shiftRight.add(ECConstants.ONE);
        }
        return new SimpleBigDecimal(shiftRight, i2);
    }

    public static BigInteger[] getLucas(byte b, int i, boolean z) {
        BigInteger bigInteger;
        BigInteger bigInteger2;
        if (b == 1 || b == -1) {
            if (z) {
                bigInteger = ECConstants.TWO;
                bigInteger2 = BigInteger.valueOf(b);
            } else {
                bigInteger = ECConstants.ZERO;
                bigInteger2 = ECConstants.ONE;
            }
            int i2 = 1;
            while (i2 < i) {
                i2++;
                BigInteger bigInteger3 = bigInteger2;
                bigInteger2 = (b < 0 ? bigInteger2.negate() : bigInteger2).subtract(bigInteger.shiftLeft(1));
                bigInteger = bigInteger3;
            }
            return new BigInteger[]{bigInteger, bigInteger2};
        }
        throw new IllegalArgumentException("mu must be 1 or -1");
    }

    public static byte getMu(int i) {
        return (byte) (i == 0 ? -1 : 1);
    }

    public static byte getMu(ECCurve.AbstractF2m abstractF2m) {
        if (abstractF2m.isKoblitz()) {
            return abstractF2m.getA().isZero() ? (byte) -1 : (byte) 1;
        }
        throw new IllegalArgumentException("No Koblitz curve (ABC), TNAF multiplication not possible");
    }

    public static byte getMu(ECFieldElement eCFieldElement) {
        return (byte) (eCFieldElement.isZero() ? -1 : 1);
    }

    public static ECPoint.AbstractF2m[] getPreComp(ECPoint.AbstractF2m abstractF2m, byte b) {
        ECPoint.AbstractF2m abstractF2m2 = (ECPoint.AbstractF2m) abstractF2m.negate();
        byte[][] bArr = b == 0 ? alpha0Tnaf : alpha1Tnaf;
        ECPoint.AbstractF2m[] abstractF2mArr = new ECPoint.AbstractF2m[(bArr.length + 1) >>> 1];
        abstractF2mArr[0] = abstractF2m;
        int length = bArr.length;
        for (int i = 3; i < length; i += 2) {
            abstractF2mArr[i >>> 1] = multiplyFromTnaf(abstractF2m, abstractF2m2, bArr[i]);
        }
        abstractF2m.getCurve().normalizeAll(abstractF2mArr);
        return abstractF2mArr;
    }

    protected static int getShiftsForCofactor(BigInteger bigInteger) {
        if (bigInteger != null) {
            if (bigInteger.equals(ECConstants.TWO)) {
                return 1;
            }
            if (bigInteger.equals(ECConstants.FOUR)) {
                return 2;
            }
        }
        throw new IllegalArgumentException("h (Cofactor) must be 2 or 4");
    }

    public static BigInteger[] getSi(int i, int i2, BigInteger bigInteger) {
        byte mu = getMu(i2);
        int shiftsForCofactor = getShiftsForCofactor(bigInteger);
        BigInteger[] lucas = getLucas(mu, (i + 3) - i2, false);
        if (mu == 1) {
            lucas[0] = lucas[0].negate();
            lucas[1] = lucas[1].negate();
        }
        return new BigInteger[]{ECConstants.ONE.add(lucas[1]).shiftRight(shiftsForCofactor), ECConstants.ONE.add(lucas[0]).shiftRight(shiftsForCofactor).negate()};
    }

    public static BigInteger[] getSi(ECCurve.AbstractF2m abstractF2m) {
        if (abstractF2m.isKoblitz()) {
            return getSi(abstractF2m.getFieldSize(), abstractF2m.getA().toBigInteger().intValue(), abstractF2m.getCofactor());
        }
        throw new IllegalArgumentException("si is defined for Koblitz curves only");
    }

    public static BigInteger getTw(byte b, int i) {
        if (i == 4) {
            return b == 1 ? BigInteger.valueOf(6L) : BigInteger.valueOf(10L);
        }
        BigInteger[] lucas = getLucas(b, i, false);
        BigInteger bit = ECConstants.ZERO.setBit(i);
        return lucas[0].shiftLeft(1).multiply(lucas[1].modInverse(bit)).mod(bit);
    }

    public static ECPoint.AbstractF2m multiplyFromTnaf(ECPoint.AbstractF2m abstractF2m, ECPoint.AbstractF2m abstractF2m2, byte[] bArr) {
        ECPoint.AbstractF2m abstractF2m3 = (ECPoint.AbstractF2m) abstractF2m.getCurve().getInfinity();
        int i = 0;
        for (int length = bArr.length - 1; length >= 0; length--) {
            i++;
            byte b = bArr[length];
            if (b != 0) {
                abstractF2m3 = (ECPoint.AbstractF2m) abstractF2m3.tauPow(i).add(b > 0 ? abstractF2m : abstractF2m2);
                i = 0;
            }
        }
        return i > 0 ? abstractF2m3.tauPow(i) : abstractF2m3;
    }

    public static ECPoint.AbstractF2m multiplyRTnaf(ECPoint.AbstractF2m abstractF2m, BigInteger bigInteger) {
        ECCurve.AbstractF2m abstractF2m2 = (ECCurve.AbstractF2m) abstractF2m.getCurve();
        int intValue = abstractF2m2.getA().toBigInteger().intValue();
        return multiplyTnaf(abstractF2m, partModReduction(abstractF2m2, bigInteger, (byte) intValue, getMu(intValue), (byte) 10));
    }

    public static ECPoint.AbstractF2m multiplyTnaf(ECPoint.AbstractF2m abstractF2m, ZTauElement zTauElement) {
        return multiplyFromTnaf(abstractF2m, (ECPoint.AbstractF2m) abstractF2m.negate(), tauAdicNaf(getMu(((ECCurve.AbstractF2m) abstractF2m.getCurve()).getA()), zTauElement));
    }

    public static BigInteger norm(byte b, ZTauElement zTauElement) {
        BigInteger subtract;
        BigInteger multiply = zTauElement.f1018u.multiply(zTauElement.f1018u);
        if (b == 1) {
            subtract = zTauElement.f1019v.shiftLeft(1).add(zTauElement.f1018u);
        } else if (b != -1) {
            throw new IllegalArgumentException("mu must be 1 or -1");
        } else {
            subtract = zTauElement.f1019v.shiftLeft(1).subtract(zTauElement.f1018u);
        }
        return subtract.multiply(zTauElement.f1019v).add(multiply);
    }

    public static SimpleBigDecimal norm(byte b, SimpleBigDecimal simpleBigDecimal, SimpleBigDecimal simpleBigDecimal2) {
        SimpleBigDecimal subtract;
        SimpleBigDecimal multiply = simpleBigDecimal.multiply(simpleBigDecimal);
        SimpleBigDecimal multiply2 = simpleBigDecimal.multiply(simpleBigDecimal2);
        SimpleBigDecimal shiftLeft = simpleBigDecimal2.multiply(simpleBigDecimal2).shiftLeft(1);
        if (b == 1) {
            subtract = multiply.add(multiply2);
        } else if (b != -1) {
            throw new IllegalArgumentException("mu must be 1 or -1");
        } else {
            subtract = multiply.subtract(multiply2);
        }
        return subtract.add(shiftLeft);
    }

    public static ZTauElement partModReduction(ECCurve.AbstractF2m abstractF2m, BigInteger bigInteger, byte b, byte b2, byte b3) {
        int fieldSize = abstractF2m.getFieldSize();
        BigInteger[] si = abstractF2m.getSi();
        BigInteger add = b2 == 1 ? si[0].add(si[1]) : si[0].subtract(si[1]);
        BigInteger subtract = abstractF2m.isKoblitz() ? ECConstants.ONE.shiftLeft(fieldSize).add(ECConstants.ONE).subtract(abstractF2m.getOrder().multiply(abstractF2m.getCofactor())) : getLucas(b2, fieldSize, true)[1];
        ZTauElement round = round(approximateDivisionByN(bigInteger, si[0], subtract, b, fieldSize, b3), approximateDivisionByN(bigInteger, si[1], subtract, b, fieldSize, b3), b2);
        return new ZTauElement(bigInteger.subtract(add.multiply(round.f1018u)).subtract(si[1].multiply(round.f1019v).shiftLeft(1)), si[1].multiply(round.f1018u).subtract(si[0].multiply(round.f1019v)));
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x0066, code lost:
        if (r5.compareTo(org.bouncycastle.math.p016ec.Tnaf.MINUS_ONE) < 0) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x0083, code lost:
        if (r5.compareTo(org.bouncycastle.math.p016ec.ECConstants.ONE) >= 0) goto L25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x008c, code lost:
        if (r7.compareTo(org.bouncycastle.math.p016ec.Tnaf.MINUS_TWO) < 0) goto L25;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static org.bouncycastle.math.p016ec.ZTauElement round(org.bouncycastle.math.p016ec.SimpleBigDecimal r7, org.bouncycastle.math.p016ec.SimpleBigDecimal r8, byte r9) {
        /*
            int r0 = r7.getScale()
            int r1 = r8.getScale()
            if (r1 != r0) goto La9
            r0 = -1
            r1 = 1
            if (r9 == r1) goto L19
            if (r9 != r0) goto L11
            goto L19
        L11:
            java.lang.IllegalArgumentException r7 = new java.lang.IllegalArgumentException
            java.lang.String r8 = "mu must be 1 or -1"
            r7.<init>(r8)
            throw r7
        L19:
            java.math.BigInteger r2 = r7.round()
            java.math.BigInteger r3 = r8.round()
            org.bouncycastle.math.ec.SimpleBigDecimal r7 = r7.subtract(r2)
            org.bouncycastle.math.ec.SimpleBigDecimal r8 = r8.subtract(r3)
            org.bouncycastle.math.ec.SimpleBigDecimal r4 = r7.add(r7)
            if (r9 != r1) goto L34
            org.bouncycastle.math.ec.SimpleBigDecimal r4 = r4.add(r8)
            goto L38
        L34:
            org.bouncycastle.math.ec.SimpleBigDecimal r4 = r4.subtract(r8)
        L38:
            org.bouncycastle.math.ec.SimpleBigDecimal r5 = r8.add(r8)
            org.bouncycastle.math.ec.SimpleBigDecimal r5 = r5.add(r8)
            org.bouncycastle.math.ec.SimpleBigDecimal r8 = r5.add(r8)
            if (r9 != r1) goto L4f
            org.bouncycastle.math.ec.SimpleBigDecimal r5 = r7.subtract(r5)
            org.bouncycastle.math.ec.SimpleBigDecimal r7 = r7.add(r8)
            goto L57
        L4f:
            org.bouncycastle.math.ec.SimpleBigDecimal r5 = r7.add(r5)
            org.bouncycastle.math.ec.SimpleBigDecimal r7 = r7.subtract(r8)
        L57:
            java.math.BigInteger r8 = org.bouncycastle.math.p016ec.ECConstants.ONE
            int r8 = r4.compareTo(r8)
            r6 = 0
            if (r8 < 0) goto L69
            java.math.BigInteger r8 = org.bouncycastle.math.p016ec.Tnaf.MINUS_ONE
            int r8 = r5.compareTo(r8)
            if (r8 >= 0) goto L75
            goto L71
        L69:
            java.math.BigInteger r8 = org.bouncycastle.math.p016ec.ECConstants.TWO
            int r8 = r7.compareTo(r8)
            if (r8 < 0) goto L74
        L71:
            r1 = r6
            r6 = r9
            goto L75
        L74:
            r1 = r6
        L75:
            java.math.BigInteger r8 = org.bouncycastle.math.p016ec.Tnaf.MINUS_ONE
            int r8 = r4.compareTo(r8)
            if (r8 >= 0) goto L86
            java.math.BigInteger r7 = org.bouncycastle.math.p016ec.ECConstants.ONE
            int r7 = r5.compareTo(r7)
            if (r7 < 0) goto L91
            goto L8e
        L86:
            java.math.BigInteger r8 = org.bouncycastle.math.p016ec.Tnaf.MINUS_TWO
            int r7 = r7.compareTo(r8)
            if (r7 >= 0) goto L90
        L8e:
            int r7 = -r9
            byte r6 = (byte) r7
        L90:
            r0 = r1
        L91:
            long r7 = (long) r0
            java.math.BigInteger r7 = java.math.BigInteger.valueOf(r7)
            java.math.BigInteger r7 = r2.add(r7)
            long r8 = (long) r6
            java.math.BigInteger r8 = java.math.BigInteger.valueOf(r8)
            java.math.BigInteger r8 = r3.add(r8)
            org.bouncycastle.math.ec.ZTauElement r9 = new org.bouncycastle.math.ec.ZTauElement
            r9.<init>(r7, r8)
            return r9
        La9:
            java.lang.IllegalArgumentException r7 = new java.lang.IllegalArgumentException
            java.lang.String r8 = "lambda0 and lambda1 do not have same scale"
            r7.<init>(r8)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.math.p016ec.Tnaf.round(org.bouncycastle.math.ec.SimpleBigDecimal, org.bouncycastle.math.ec.SimpleBigDecimal, byte):org.bouncycastle.math.ec.ZTauElement");
    }

    public static ECPoint.AbstractF2m tau(ECPoint.AbstractF2m abstractF2m) {
        return abstractF2m.tau();
    }

    public static byte[] tauAdicNaf(byte b, ZTauElement zTauElement) {
        if (b != 1 && b != -1) {
            throw new IllegalArgumentException("mu must be 1 or -1");
        }
        int bitLength = norm(b, zTauElement).bitLength();
        byte[] bArr = new byte[bitLength > 30 ? bitLength + 4 : 34];
        BigInteger bigInteger = zTauElement.f1018u;
        BigInteger bigInteger2 = zTauElement.f1019v;
        int i = 0;
        int i2 = 0;
        while (true) {
            if (bigInteger.equals(ECConstants.ZERO) && bigInteger2.equals(ECConstants.ZERO)) {
                int i3 = i + 1;
                byte[] bArr2 = new byte[i3];
                System.arraycopy(bArr, 0, bArr2, 0, i3);
                return bArr2;
            }
            if (bigInteger.testBit(0)) {
                byte intValue = (byte) ECConstants.TWO.subtract(bigInteger.subtract(bigInteger2.shiftLeft(1)).mod(ECConstants.FOUR)).intValue();
                bArr[i2] = intValue;
                bigInteger = intValue == 1 ? bigInteger.clearBit(0) : bigInteger.add(ECConstants.ONE);
                i = i2;
            } else {
                bArr[i2] = 0;
            }
            BigInteger shiftRight = bigInteger.shiftRight(1);
            BigInteger add = b == 1 ? bigInteger2.add(shiftRight) : bigInteger2.subtract(shiftRight);
            BigInteger negate = bigInteger.shiftRight(1).negate();
            i2++;
            bigInteger = add;
            bigInteger2 = negate;
        }
    }

    public static byte[] tauAdicWNaf(byte b, ZTauElement zTauElement, int i, int i2, ZTauElement[] zTauElementArr) {
        if (b == 1 || b == -1) {
            int bitLength = norm(b, zTauElement).bitLength();
            byte[] bArr = new byte[bitLength > 30 ? bitLength + 4 + i : i + 34];
            int i3 = (1 << i) - 1;
            int i4 = 32 - i;
            BigInteger bigInteger = zTauElement.f1018u;
            BigInteger bigInteger2 = zTauElement.f1019v;
            int i5 = 0;
            while (true) {
                if (bigInteger.bitLength() <= 62 && bigInteger2.bitLength() <= 62) {
                    break;
                }
                if (bigInteger.testBit(0)) {
                    int intValue = bigInteger.intValue() + (bigInteger2.intValue() * i2);
                    int i6 = intValue & i3;
                    bArr[i5] = (byte) ((intValue << i4) >> i4);
                    bigInteger = bigInteger.subtract(zTauElementArr[i6].f1018u);
                    bigInteger2 = bigInteger2.subtract(zTauElementArr[i6].f1019v);
                }
                i5++;
                BigInteger shiftRight = bigInteger.shiftRight(1);
                BigInteger add = b == 1 ? bigInteger2.add(shiftRight) : bigInteger2.subtract(shiftRight);
                BigInteger negate = shiftRight.negate();
                bigInteger = add;
                bigInteger2 = negate;
            }
            long longValueExact = BigIntegers.longValueExact(bigInteger);
            long longValueExact2 = BigIntegers.longValueExact(bigInteger2);
            while ((longValueExact | longValueExact2) != 0) {
                if ((1 & longValueExact) != 0) {
                    int i7 = ((int) longValueExact) + (((int) longValueExact2) * i2);
                    int i8 = i7 & i3;
                    bArr[i5] = (byte) ((i7 << i4) >> i4);
                    longValueExact -= zTauElementArr[i8].f1018u.intValue();
                    longValueExact2 -= zTauElementArr[i8].f1019v.intValue();
                }
                i5++;
                long j = longValueExact >> 1;
                long j2 = b == 1 ? longValueExact2 + j : longValueExact2 - j;
                long j3 = -j;
                longValueExact = j2;
                longValueExact2 = j3;
            }
            return bArr;
        }
        throw new IllegalArgumentException("mu must be 1 or -1");
    }
}