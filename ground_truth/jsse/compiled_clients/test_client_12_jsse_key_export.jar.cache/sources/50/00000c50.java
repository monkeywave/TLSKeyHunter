package org.bouncycastle.math.p010ec;

import java.math.BigInteger;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECPoint;

/* JADX INFO: Access modifiers changed from: package-private */
/* renamed from: org.bouncycastle.math.ec.Tnaf */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/Tnaf.class */
public class Tnaf {
    public static final byte WIDTH = 4;
    public static final byte POW_2_WIDTH = 16;
    private static final BigInteger MINUS_ONE = ECConstants.ONE.negate();
    private static final BigInteger MINUS_TWO = ECConstants.TWO.negate();
    private static final BigInteger MINUS_THREE = ECConstants.THREE.negate();
    public static final ZTauElement[] alpha0 = {null, new ZTauElement(ECConstants.ONE, ECConstants.ZERO), null, new ZTauElement(MINUS_THREE, MINUS_ONE), null, new ZTauElement(MINUS_ONE, MINUS_ONE), null, new ZTauElement(ECConstants.ONE, MINUS_ONE), null};
    public static final byte[][] alpha0Tnaf = {0, new byte[]{1}, 0, new byte[]{-1, 0, 1}, 0, new byte[]{1, 0, 1}, 0, new byte[]{-1, 0, 0, 1}};
    public static final ZTauElement[] alpha1 = {null, new ZTauElement(ECConstants.ONE, ECConstants.ZERO), null, new ZTauElement(MINUS_THREE, ECConstants.ONE), null, new ZTauElement(MINUS_ONE, ECConstants.ONE), null, new ZTauElement(ECConstants.ONE, ECConstants.ONE), null};
    public static final byte[][] alpha1Tnaf = {0, new byte[]{1}, 0, new byte[]{-1, 0, 1}, 0, new byte[]{1, 0, 1}, 0, new byte[]{-1, 0, 0, -1}};

    Tnaf() {
    }

    public static BigInteger norm(byte b, ZTauElement zTauElement) {
        BigInteger add;
        BigInteger multiply = zTauElement.f679u.multiply(zTauElement.f679u);
        BigInteger multiply2 = zTauElement.f679u.multiply(zTauElement.f680v);
        BigInteger shiftLeft = zTauElement.f680v.multiply(zTauElement.f680v).shiftLeft(1);
        if (b == 1) {
            add = multiply.add(multiply2).add(shiftLeft);
        } else if (b != -1) {
            throw new IllegalArgumentException("mu must be 1 or -1");
        } else {
            add = multiply.subtract(multiply2).add(shiftLeft);
        }
        return add;
    }

    public static SimpleBigDecimal norm(byte b, SimpleBigDecimal simpleBigDecimal, SimpleBigDecimal simpleBigDecimal2) {
        SimpleBigDecimal add;
        SimpleBigDecimal multiply = simpleBigDecimal.multiply(simpleBigDecimal);
        SimpleBigDecimal multiply2 = simpleBigDecimal.multiply(simpleBigDecimal2);
        SimpleBigDecimal shiftLeft = simpleBigDecimal2.multiply(simpleBigDecimal2).shiftLeft(1);
        if (b == 1) {
            add = multiply.add(multiply2).add(shiftLeft);
        } else if (b != -1) {
            throw new IllegalArgumentException("mu must be 1 or -1");
        } else {
            add = multiply.subtract(multiply2).add(shiftLeft);
        }
        return add;
    }

    public static ZTauElement round(SimpleBigDecimal simpleBigDecimal, SimpleBigDecimal simpleBigDecimal2, byte b) {
        SimpleBigDecimal add;
        SimpleBigDecimal subtract;
        if (simpleBigDecimal2.getScale() != simpleBigDecimal.getScale()) {
            throw new IllegalArgumentException("lambda0 and lambda1 do not have same scale");
        }
        if (b == 1 || b == -1) {
            BigInteger round = simpleBigDecimal.round();
            BigInteger round2 = simpleBigDecimal2.round();
            SimpleBigDecimal subtract2 = simpleBigDecimal.subtract(round);
            SimpleBigDecimal subtract3 = simpleBigDecimal2.subtract(round2);
            SimpleBigDecimal add2 = subtract2.add(subtract2);
            SimpleBigDecimal add3 = b == 1 ? add2.add(subtract3) : add2.subtract(subtract3);
            SimpleBigDecimal add4 = subtract3.add(subtract3).add(subtract3);
            SimpleBigDecimal add5 = add4.add(subtract3);
            if (b == 1) {
                add = subtract2.subtract(add4);
                subtract = subtract2.add(add5);
            } else {
                add = subtract2.add(add4);
                subtract = subtract2.subtract(add5);
            }
            int i = 0;
            byte b2 = 0;
            if (add3.compareTo(ECConstants.ONE) >= 0) {
                if (add.compareTo(MINUS_ONE) < 0) {
                    b2 = b;
                } else {
                    i = 1;
                }
            } else if (subtract.compareTo(ECConstants.TWO) >= 0) {
                b2 = b;
            }
            if (add3.compareTo(MINUS_ONE) < 0) {
                if (add.compareTo(ECConstants.ONE) >= 0) {
                    b2 = (byte) (-b);
                } else {
                    i = -1;
                }
            } else if (subtract.compareTo(MINUS_TWO) < 0) {
                b2 = (byte) (-b);
            }
            return new ZTauElement(round.add(BigInteger.valueOf(i)), round2.add(BigInteger.valueOf(b2)));
        }
        throw new IllegalArgumentException("mu must be 1 or -1");
    }

    public static SimpleBigDecimal approximateDivisionByN(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, byte b, int i, int i2) {
        int i3 = ((i + 5) / 2) + i2;
        BigInteger multiply = bigInteger2.multiply(bigInteger.shiftRight(((i - i3) - 2) + b));
        BigInteger add = multiply.add(bigInteger3.multiply(multiply.shiftRight(i)));
        BigInteger shiftRight = add.shiftRight(i3 - i2);
        if (add.testBit((i3 - i2) - 1)) {
            shiftRight = shiftRight.add(ECConstants.ONE);
        }
        return new SimpleBigDecimal(shiftRight, i2);
    }

    public static byte[] tauAdicNaf(byte b, ZTauElement zTauElement) {
        if (b != 1 && b != -1) {
            throw new IllegalArgumentException("mu must be 1 or -1");
        }
        int bitLength = norm(b, zTauElement).bitLength();
        byte[] bArr = new byte[bitLength > 30 ? bitLength + 4 : 34];
        int i = 0;
        int i2 = 0;
        BigInteger bigInteger = zTauElement.f679u;
        BigInteger bigInteger2 = zTauElement.f680v;
        while (true) {
            if (bigInteger.equals(ECConstants.ZERO) && bigInteger2.equals(ECConstants.ZERO)) {
                int i3 = i2 + 1;
                byte[] bArr2 = new byte[i3];
                System.arraycopy(bArr, 0, bArr2, 0, i3);
                return bArr2;
            }
            if (bigInteger.testBit(0)) {
                bArr[i] = (byte) ECConstants.TWO.subtract(bigInteger.subtract(bigInteger2.shiftLeft(1)).mod(ECConstants.FOUR)).intValue();
                bigInteger = bArr[i] == 1 ? bigInteger.clearBit(0) : bigInteger.add(ECConstants.ONE);
                i2 = i;
            } else {
                bArr[i] = 0;
            }
            BigInteger bigInteger3 = bigInteger;
            BigInteger shiftRight = bigInteger.shiftRight(1);
            bigInteger = b == 1 ? bigInteger2.add(shiftRight) : bigInteger2.subtract(shiftRight);
            bigInteger2 = bigInteger3.shiftRight(1).negate();
            i++;
        }
    }

    public static ECPoint.AbstractF2m tau(ECPoint.AbstractF2m abstractF2m) {
        return abstractF2m.tau();
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

    public static byte getMu(int i) {
        return (byte) (i == 0 ? -1 : 1);
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
            for (int i2 = 1; i2 < i; i2++) {
                bigInteger = bigInteger2;
                bigInteger2 = (b == 1 ? bigInteger2 : bigInteger2.negate()).subtract(bigInteger.shiftLeft(1));
            }
            return new BigInteger[]{bigInteger, bigInteger2};
        }
        throw new IllegalArgumentException("mu must be 1 or -1");
    }

    public static BigInteger getTw(byte b, int i) {
        if (i == 4) {
            return b == 1 ? BigInteger.valueOf(6L) : BigInteger.valueOf(10L);
        }
        BigInteger[] lucas = getLucas(b, i, false);
        BigInteger bit = ECConstants.ZERO.setBit(i);
        return ECConstants.TWO.multiply(lucas[0]).multiply(lucas[1].modInverse(bit)).mod(bit);
    }

    public static BigInteger[] getSi(ECCurve.AbstractF2m abstractF2m) {
        if (abstractF2m.isKoblitz()) {
            int fieldSize = abstractF2m.getFieldSize();
            int intValue = abstractF2m.getA().toBigInteger().intValue();
            byte mu = getMu(intValue);
            int shiftsForCofactor = getShiftsForCofactor(abstractF2m.getCofactor());
            BigInteger[] lucas = getLucas(mu, (fieldSize + 3) - intValue, false);
            if (mu == 1) {
                lucas[0] = lucas[0].negate();
                lucas[1] = lucas[1].negate();
            }
            return new BigInteger[]{ECConstants.ONE.add(lucas[1]).shiftRight(shiftsForCofactor), ECConstants.ONE.add(lucas[0]).shiftRight(shiftsForCofactor).negate()};
        }
        throw new IllegalArgumentException("si is defined for Koblitz curves only");
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

    public static ZTauElement partModReduction(BigInteger bigInteger, int i, byte b, BigInteger[] bigIntegerArr, byte b2, byte b3) {
        BigInteger add = b2 == 1 ? bigIntegerArr[0].add(bigIntegerArr[1]) : bigIntegerArr[0].subtract(bigIntegerArr[1]);
        BigInteger bigInteger2 = getLucas(b2, i, true)[1];
        ZTauElement round = round(approximateDivisionByN(bigInteger, bigIntegerArr[0], bigInteger2, b, i, b3), approximateDivisionByN(bigInteger, bigIntegerArr[1], bigInteger2, b, i, b3), b2);
        return new ZTauElement(bigInteger.subtract(add.multiply(round.f679u)).subtract(BigInteger.valueOf(2L).multiply(bigIntegerArr[1]).multiply(round.f680v)), bigIntegerArr[1].multiply(round.f679u).subtract(bigIntegerArr[0].multiply(round.f680v)));
    }

    public static ECPoint.AbstractF2m multiplyRTnaf(ECPoint.AbstractF2m abstractF2m, BigInteger bigInteger) {
        ECCurve.AbstractF2m abstractF2m2 = (ECCurve.AbstractF2m) abstractF2m.getCurve();
        int fieldSize = abstractF2m2.getFieldSize();
        int intValue = abstractF2m2.getA().toBigInteger().intValue();
        return multiplyTnaf(abstractF2m, partModReduction(bigInteger, fieldSize, (byte) intValue, abstractF2m2.getSi(), getMu(intValue), (byte) 10));
    }

    public static ECPoint.AbstractF2m multiplyTnaf(ECPoint.AbstractF2m abstractF2m, ZTauElement zTauElement) {
        return multiplyFromTnaf(abstractF2m, tauAdicNaf(getMu(((ECCurve.AbstractF2m) abstractF2m.getCurve()).getA()), zTauElement));
    }

    public static ECPoint.AbstractF2m multiplyFromTnaf(ECPoint.AbstractF2m abstractF2m, byte[] bArr) {
        ECPoint.AbstractF2m abstractF2m2 = (ECPoint.AbstractF2m) abstractF2m.getCurve().getInfinity();
        ECPoint.AbstractF2m abstractF2m3 = (ECPoint.AbstractF2m) abstractF2m.negate();
        int i = 0;
        for (int length = bArr.length - 1; length >= 0; length--) {
            i++;
            byte b = bArr[length];
            if (b != 0) {
                ECPoint.AbstractF2m tauPow = abstractF2m2.tauPow(i);
                i = 0;
                abstractF2m2 = (ECPoint.AbstractF2m) tauPow.add(b > 0 ? abstractF2m : abstractF2m3);
            }
        }
        if (i > 0) {
            abstractF2m2 = abstractF2m2.tauPow(i);
        }
        return abstractF2m2;
    }

    public static byte[] tauAdicWNaf(byte b, ZTauElement zTauElement, byte b2, BigInteger bigInteger, BigInteger bigInteger2, ZTauElement[] zTauElementArr) {
        if (b != 1 && b != -1) {
            throw new IllegalArgumentException("mu must be 1 or -1");
        }
        int bitLength = norm(b, zTauElement).bitLength();
        byte[] bArr = new byte[bitLength > 30 ? bitLength + 4 + b2 : 34 + b2];
        BigInteger shiftRight = bigInteger.shiftRight(1);
        BigInteger bigInteger3 = zTauElement.f679u;
        BigInteger bigInteger4 = zTauElement.f680v;
        int i = 0;
        while (true) {
            if (bigInteger3.equals(ECConstants.ZERO) && bigInteger4.equals(ECConstants.ZERO)) {
                return bArr;
            }
            if (bigInteger3.testBit(0)) {
                BigInteger mod = bigInteger3.add(bigInteger4.multiply(bigInteger2)).mod(bigInteger);
                byte intValue = mod.compareTo(shiftRight) >= 0 ? (byte) mod.subtract(bigInteger).intValue() : (byte) mod.intValue();
                bArr[i] = intValue;
                boolean z = true;
                if (intValue < 0) {
                    z = false;
                    intValue = (byte) (-intValue);
                }
                if (z) {
                    bigInteger3 = bigInteger3.subtract(zTauElementArr[intValue].f679u);
                    bigInteger4 = bigInteger4.subtract(zTauElementArr[intValue].f680v);
                } else {
                    bigInteger3 = bigInteger3.add(zTauElementArr[intValue].f679u);
                    bigInteger4 = bigInteger4.add(zTauElementArr[intValue].f680v);
                }
            } else {
                bArr[i] = 0;
            }
            BigInteger bigInteger5 = bigInteger3;
            bigInteger3 = b == 1 ? bigInteger4.add(bigInteger3.shiftRight(1)) : bigInteger4.subtract(bigInteger3.shiftRight(1));
            bigInteger4 = bigInteger5.shiftRight(1).negate();
            i++;
        }
    }

    public static ECPoint.AbstractF2m[] getPreComp(ECPoint.AbstractF2m abstractF2m, byte b) {
        byte[][] bArr = b == 0 ? alpha0Tnaf : alpha1Tnaf;
        ECPoint.AbstractF2m[] abstractF2mArr = new ECPoint.AbstractF2m[(bArr.length + 1) >>> 1];
        abstractF2mArr[0] = abstractF2m;
        int length = bArr.length;
        for (int i = 3; i < length; i += 2) {
            abstractF2mArr[i >>> 1] = multiplyFromTnaf(abstractF2m, bArr[i]);
        }
        abstractF2m.getCurve().normalizeAll(abstractF2mArr);
        return abstractF2mArr;
    }
}