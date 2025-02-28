package org.bouncycastle.math.p010ec;

import java.math.BigInteger;
import javassist.bytecode.Opcode;
import javassist.compiler.TokenId;

/* renamed from: org.bouncycastle.math.ec.WNafUtil */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/WNafUtil.class */
public abstract class WNafUtil {
    public static final String PRECOMP_NAME = "bc_wnaf";
    private static final int MAX_WIDTH = 16;
    private static final int[] DEFAULT_WINDOW_SIZE_CUTOFFS = {13, 41, Opcode.LSHL, TokenId.SWITCH, 897, 2305};
    private static final byte[] EMPTY_BYTES = new byte[0];
    private static final int[] EMPTY_INTS = new int[0];
    private static final ECPoint[] EMPTY_POINTS = new ECPoint[0];

    public static void configureBasepoint(ECPoint eCPoint) {
        ECCurve curve = eCPoint.getCurve();
        if (null == curve) {
            return;
        }
        BigInteger order = curve.getOrder();
        final int min = Math.min(16, getWindowSize(null == order ? curve.getFieldSize() + 1 : order.bitLength()) + 3);
        curve.precompute(eCPoint, PRECOMP_NAME, new PreCompCallback() { // from class: org.bouncycastle.math.ec.WNafUtil.1
            @Override // org.bouncycastle.math.p010ec.PreCompCallback
            public PreCompInfo precompute(PreCompInfo preCompInfo) {
                WNafPreCompInfo wNafPreCompInfo = preCompInfo instanceof WNafPreCompInfo ? (WNafPreCompInfo) preCompInfo : null;
                if (null != wNafPreCompInfo && wNafPreCompInfo.getConfWidth() == min) {
                    wNafPreCompInfo.setPromotionCountdown(0);
                    return wNafPreCompInfo;
                }
                WNafPreCompInfo wNafPreCompInfo2 = new WNafPreCompInfo();
                wNafPreCompInfo2.setPromotionCountdown(0);
                wNafPreCompInfo2.setConfWidth(min);
                if (null != wNafPreCompInfo) {
                    wNafPreCompInfo2.setPreComp(wNafPreCompInfo.getPreComp());
                    wNafPreCompInfo2.setPreCompNeg(wNafPreCompInfo.getPreCompNeg());
                    wNafPreCompInfo2.setTwice(wNafPreCompInfo.getTwice());
                    wNafPreCompInfo2.setWidth(wNafPreCompInfo.getWidth());
                }
                return wNafPreCompInfo2;
            }
        });
    }

    public static int[] generateCompactNaf(BigInteger bigInteger) {
        if ((bigInteger.bitLength() >>> 16) != 0) {
            throw new IllegalArgumentException("'k' must have bitlength < 2^16");
        }
        if (bigInteger.signum() == 0) {
            return EMPTY_INTS;
        }
        BigInteger add = bigInteger.shiftLeft(1).add(bigInteger);
        int bitLength = add.bitLength();
        int[] iArr = new int[bitLength >> 1];
        BigInteger xor = add.xor(bigInteger);
        int i = bitLength - 1;
        int i2 = 0;
        int i3 = 0;
        int i4 = 1;
        while (i4 < i) {
            if (xor.testBit(i4)) {
                int i5 = i2;
                i2++;
                iArr[i5] = ((bigInteger.testBit(i4) ? -1 : 1) << 16) | i3;
                i3 = 1;
                i4++;
            } else {
                i3++;
            }
            i4++;
        }
        int i6 = i2;
        int i7 = i2 + 1;
        iArr[i6] = 65536 | i3;
        if (iArr.length > i7) {
            iArr = trim(iArr, i7);
        }
        return iArr;
    }

    public static int[] generateCompactWindowNaf(int i, BigInteger bigInteger) {
        if (i == 2) {
            return generateCompactNaf(bigInteger);
        }
        if (i < 2 || i > 16) {
            throw new IllegalArgumentException("'width' must be in the range [2, 16]");
        }
        if ((bigInteger.bitLength() >>> 16) != 0) {
            throw new IllegalArgumentException("'k' must have bitlength < 2^16");
        }
        if (bigInteger.signum() == 0) {
            return EMPTY_INTS;
        }
        int[] iArr = new int[(bigInteger.bitLength() / i) + 1];
        int i2 = 1 << i;
        int i3 = i2 - 1;
        int i4 = i2 >>> 1;
        boolean z = false;
        int i5 = 0;
        int i6 = 0;
        while (i6 <= bigInteger.bitLength()) {
            if (bigInteger.testBit(i6) == z) {
                i6++;
            } else {
                bigInteger = bigInteger.shiftRight(i6);
                int intValue = bigInteger.intValue() & i3;
                if (z) {
                    intValue++;
                }
                z = (intValue & i4) != 0;
                if (z) {
                    intValue -= i2;
                }
                int i7 = i5 > 0 ? i6 - 1 : i6;
                int i8 = i5;
                i5++;
                iArr[i8] = (intValue << 16) | i7;
                i6 = i;
            }
        }
        if (iArr.length > i5) {
            iArr = trim(iArr, i5);
        }
        return iArr;
    }

    public static byte[] generateJSF(BigInteger bigInteger, BigInteger bigInteger2) {
        byte[] bArr = new byte[Math.max(bigInteger.bitLength(), bigInteger2.bitLength()) + 1];
        BigInteger bigInteger3 = bigInteger;
        BigInteger bigInteger4 = bigInteger2;
        int i = 0;
        int i2 = 0;
        int i3 = 0;
        int i4 = 0;
        while (true) {
            if ((i2 | i3) == 0 && bigInteger3.bitLength() <= i4 && bigInteger4.bitLength() <= i4) {
                break;
            }
            int intValue = ((bigInteger3.intValue() >>> i4) + i2) & 7;
            int intValue2 = ((bigInteger4.intValue() >>> i4) + i3) & 7;
            int i5 = intValue & 1;
            if (i5 != 0) {
                i5 -= intValue & 2;
                if (intValue + i5 == 4 && (intValue2 & 3) == 2) {
                    i5 = -i5;
                }
            }
            int i6 = intValue2 & 1;
            if (i6 != 0) {
                i6 -= intValue2 & 2;
                if (intValue2 + i6 == 4 && (intValue & 3) == 2) {
                    i6 = -i6;
                }
            }
            if ((i2 << 1) == 1 + i5) {
                i2 ^= 1;
            }
            if ((i3 << 1) == 1 + i6) {
                i3 ^= 1;
            }
            i4++;
            if (i4 == 30) {
                i4 = 0;
                bigInteger3 = bigInteger3.shiftRight(30);
                bigInteger4 = bigInteger4.shiftRight(30);
            }
            int i7 = i;
            i++;
            bArr[i7] = (byte) ((i5 << 4) | (i6 & 15));
        }
        if (bArr.length > i) {
            bArr = trim(bArr, i);
        }
        return bArr;
    }

    public static byte[] generateNaf(BigInteger bigInteger) {
        if (bigInteger.signum() == 0) {
            return EMPTY_BYTES;
        }
        BigInteger add = bigInteger.shiftLeft(1).add(bigInteger);
        int bitLength = add.bitLength() - 1;
        byte[] bArr = new byte[bitLength];
        BigInteger xor = add.xor(bigInteger);
        int i = 1;
        while (i < bitLength) {
            if (xor.testBit(i)) {
                bArr[i - 1] = (byte) (bigInteger.testBit(i) ? -1 : 1);
                i++;
            }
            i++;
        }
        bArr[bitLength - 1] = 1;
        return bArr;
    }

    public static byte[] generateWindowNaf(int i, BigInteger bigInteger) {
        if (i == 2) {
            return generateNaf(bigInteger);
        }
        if (i < 2 || i > 8) {
            throw new IllegalArgumentException("'width' must be in the range [2, 8]");
        }
        if (bigInteger.signum() == 0) {
            return EMPTY_BYTES;
        }
        byte[] bArr = new byte[bigInteger.bitLength() + 1];
        int i2 = 1 << i;
        int i3 = i2 - 1;
        int i4 = i2 >>> 1;
        boolean z = false;
        int i5 = 0;
        int i6 = 0;
        while (i6 <= bigInteger.bitLength()) {
            if (bigInteger.testBit(i6) == z) {
                i6++;
            } else {
                bigInteger = bigInteger.shiftRight(i6);
                int intValue = bigInteger.intValue() & i3;
                if (z) {
                    intValue++;
                }
                z = (intValue & i4) != 0;
                if (z) {
                    intValue -= i2;
                }
                int i7 = i5 + (i5 > 0 ? i6 - 1 : i6);
                i5 = i7 + 1;
                bArr[i7] = (byte) intValue;
                i6 = i;
            }
        }
        if (bArr.length > i5) {
            bArr = trim(bArr, i5);
        }
        return bArr;
    }

    public static int getNafWeight(BigInteger bigInteger) {
        if (bigInteger.signum() == 0) {
            return 0;
        }
        return bigInteger.shiftLeft(1).add(bigInteger).xor(bigInteger).bitCount();
    }

    public static WNafPreCompInfo getWNafPreCompInfo(ECPoint eCPoint) {
        return getWNafPreCompInfo(eCPoint.getCurve().getPreCompInfo(eCPoint, PRECOMP_NAME));
    }

    public static WNafPreCompInfo getWNafPreCompInfo(PreCompInfo preCompInfo) {
        if (preCompInfo instanceof WNafPreCompInfo) {
            return (WNafPreCompInfo) preCompInfo;
        }
        return null;
    }

    public static int getWindowSize(int i) {
        return getWindowSize(i, DEFAULT_WINDOW_SIZE_CUTOFFS, 16);
    }

    public static int getWindowSize(int i, int i2) {
        return getWindowSize(i, DEFAULT_WINDOW_SIZE_CUTOFFS, i2);
    }

    public static int getWindowSize(int i, int[] iArr) {
        return getWindowSize(i, iArr, 16);
    }

    public static int getWindowSize(int i, int[] iArr, int i2) {
        int i3 = 0;
        while (i3 < iArr.length && i >= iArr[i3]) {
            i3++;
        }
        return Math.max(2, Math.min(i2, i3 + 2));
    }

    public static WNafPreCompInfo precompute(final ECPoint eCPoint, final int i, final boolean z) {
        final ECCurve curve = eCPoint.getCurve();
        return (WNafPreCompInfo) curve.precompute(eCPoint, PRECOMP_NAME, new PreCompCallback() { // from class: org.bouncycastle.math.ec.WNafUtil.2
            @Override // org.bouncycastle.math.p010ec.PreCompCallback
            public PreCompInfo precompute(PreCompInfo preCompInfo) {
                int length;
                WNafPreCompInfo wNafPreCompInfo = preCompInfo instanceof WNafPreCompInfo ? (WNafPreCompInfo) preCompInfo : null;
                int max = Math.max(2, Math.min(16, i));
                if (checkExisting(wNafPreCompInfo, max, 1 << (max - 2), z)) {
                    wNafPreCompInfo.decrementPromotionCountdown();
                    return wNafPreCompInfo;
                }
                WNafPreCompInfo wNafPreCompInfo2 = new WNafPreCompInfo();
                ECPoint[] eCPointArr = null;
                ECPoint[] eCPointArr2 = null;
                ECPoint eCPoint2 = null;
                if (null != wNafPreCompInfo) {
                    wNafPreCompInfo2.setPromotionCountdown(wNafPreCompInfo.decrementPromotionCountdown());
                    wNafPreCompInfo2.setConfWidth(wNafPreCompInfo.getConfWidth());
                    eCPointArr = wNafPreCompInfo.getPreComp();
                    eCPointArr2 = wNafPreCompInfo.getPreCompNeg();
                    eCPoint2 = wNafPreCompInfo.getTwice();
                }
                int min = Math.min(16, Math.max(wNafPreCompInfo2.getConfWidth(), max));
                int i2 = 1 << (min - 2);
                int i3 = 0;
                if (null == eCPointArr) {
                    eCPointArr = WNafUtil.EMPTY_POINTS;
                } else {
                    i3 = eCPointArr.length;
                }
                if (i3 < i2) {
                    eCPointArr = WNafUtil.resizeTable(eCPointArr, i2);
                    if (i2 == 1) {
                        eCPointArr[0] = eCPoint.normalize();
                    } else {
                        int i4 = i3;
                        if (i4 == 0) {
                            eCPointArr[0] = eCPoint;
                            i4 = 1;
                        }
                        ECFieldElement eCFieldElement = null;
                        if (i2 == 2) {
                            eCPointArr[1] = eCPoint.threeTimes();
                        } else {
                            ECPoint eCPoint3 = eCPoint2;
                            ECPoint eCPoint4 = eCPointArr[i4 - 1];
                            if (null == eCPoint3) {
                                eCPoint3 = eCPointArr[0].twice();
                                eCPoint2 = eCPoint3;
                                if (!eCPoint2.isInfinity() && ECAlgorithms.isFpCurve(curve) && curve.getFieldSize() >= 64) {
                                    switch (curve.getCoordinateSystem()) {
                                        case 2:
                                        case 3:
                                        case 4:
                                            eCFieldElement = eCPoint2.getZCoord(0);
                                            eCPoint3 = curve.createPoint(eCPoint2.getXCoord().toBigInteger(), eCPoint2.getYCoord().toBigInteger());
                                            ECFieldElement square = eCFieldElement.square();
                                            eCPoint4 = eCPoint4.scaleX(square).scaleY(square.multiply(eCFieldElement));
                                            if (i3 == 0) {
                                                eCPointArr[0] = eCPoint4;
                                                break;
                                            }
                                            break;
                                    }
                                }
                            }
                            while (i4 < i2) {
                                int i5 = i4;
                                i4++;
                                ECPoint add = eCPoint4.add(eCPoint3);
                                eCPoint4 = add;
                                eCPointArr[i5] = add;
                            }
                        }
                        curve.normalizeAll(eCPointArr, i3, i2 - i3, eCFieldElement);
                    }
                }
                if (z) {
                    if (null == eCPointArr2) {
                        length = 0;
                        eCPointArr2 = new ECPoint[i2];
                    } else {
                        length = eCPointArr2.length;
                        if (length < i2) {
                            eCPointArr2 = WNafUtil.resizeTable(eCPointArr2, i2);
                        }
                    }
                    while (length < i2) {
                        eCPointArr2[length] = eCPointArr[length].negate();
                        length++;
                    }
                }
                wNafPreCompInfo2.setPreComp(eCPointArr);
                wNafPreCompInfo2.setPreCompNeg(eCPointArr2);
                wNafPreCompInfo2.setTwice(eCPoint2);
                wNafPreCompInfo2.setWidth(min);
                return wNafPreCompInfo2;
            }

            private boolean checkExisting(WNafPreCompInfo wNafPreCompInfo, int i2, int i3, boolean z2) {
                return null != wNafPreCompInfo && wNafPreCompInfo.getWidth() >= Math.max(wNafPreCompInfo.getConfWidth(), i2) && checkTable(wNafPreCompInfo.getPreComp(), i3) && (!z2 || checkTable(wNafPreCompInfo.getPreCompNeg(), i3));
            }

            private boolean checkTable(ECPoint[] eCPointArr, int i2) {
                return null != eCPointArr && eCPointArr.length >= i2;
            }
        });
    }

    public static WNafPreCompInfo precomputeWithPointMap(ECPoint eCPoint, final ECPointMap eCPointMap, final WNafPreCompInfo wNafPreCompInfo, final boolean z) {
        return (WNafPreCompInfo) eCPoint.getCurve().precompute(eCPoint, PRECOMP_NAME, new PreCompCallback() { // from class: org.bouncycastle.math.ec.WNafUtil.3
            @Override // org.bouncycastle.math.p010ec.PreCompCallback
            public PreCompInfo precompute(PreCompInfo preCompInfo) {
                WNafPreCompInfo wNafPreCompInfo2 = preCompInfo instanceof WNafPreCompInfo ? (WNafPreCompInfo) preCompInfo : null;
                int width = WNafPreCompInfo.this.getWidth();
                if (checkExisting(wNafPreCompInfo2, width, WNafPreCompInfo.this.getPreComp().length, z)) {
                    wNafPreCompInfo2.decrementPromotionCountdown();
                    return wNafPreCompInfo2;
                }
                WNafPreCompInfo wNafPreCompInfo3 = new WNafPreCompInfo();
                wNafPreCompInfo3.setPromotionCountdown(WNafPreCompInfo.this.getPromotionCountdown());
                ECPoint twice = WNafPreCompInfo.this.getTwice();
                if (null != twice) {
                    wNafPreCompInfo3.setTwice(eCPointMap.map(twice));
                }
                ECPoint[] preComp = WNafPreCompInfo.this.getPreComp();
                ECPoint[] eCPointArr = new ECPoint[preComp.length];
                for (int i = 0; i < preComp.length; i++) {
                    eCPointArr[i] = eCPointMap.map(preComp[i]);
                }
                wNafPreCompInfo3.setPreComp(eCPointArr);
                wNafPreCompInfo3.setWidth(width);
                if (z) {
                    ECPoint[] eCPointArr2 = new ECPoint[eCPointArr.length];
                    for (int i2 = 0; i2 < eCPointArr2.length; i2++) {
                        eCPointArr2[i2] = eCPointArr[i2].negate();
                    }
                    wNafPreCompInfo3.setPreCompNeg(eCPointArr2);
                }
                return wNafPreCompInfo3;
            }

            private boolean checkExisting(WNafPreCompInfo wNafPreCompInfo2, int i, int i2, boolean z2) {
                return null != wNafPreCompInfo2 && wNafPreCompInfo2.getWidth() >= i && checkTable(wNafPreCompInfo2.getPreComp(), i2) && (!z2 || checkTable(wNafPreCompInfo2.getPreCompNeg(), i2));
            }

            private boolean checkTable(ECPoint[] eCPointArr, int i) {
                return null != eCPointArr && eCPointArr.length >= i;
            }
        });
    }

    private static byte[] trim(byte[] bArr, int i) {
        byte[] bArr2 = new byte[i];
        System.arraycopy(bArr, 0, bArr2, 0, bArr2.length);
        return bArr2;
    }

    private static int[] trim(int[] iArr, int i) {
        int[] iArr2 = new int[i];
        System.arraycopy(iArr, 0, iArr2, 0, iArr2.length);
        return iArr2;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static ECPoint[] resizeTable(ECPoint[] eCPointArr, int i) {
        ECPoint[] eCPointArr2 = new ECPoint[i];
        System.arraycopy(eCPointArr, 0, eCPointArr2, 0, eCPointArr.length);
        return eCPointArr2;
    }
}