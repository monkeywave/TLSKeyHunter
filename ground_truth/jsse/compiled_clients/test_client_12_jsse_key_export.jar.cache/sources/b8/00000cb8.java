package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import javassist.bytecode.Opcode;
import org.bouncycastle.math.p010ec.AbstractECLookupTable;
import org.bouncycastle.math.p010ec.ECConstants;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.p010ec.ECLookupTable;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.raw.Nat192;
import org.bouncycastle.util.encoders.Hex;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecT163R2Curve */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecT163R2Curve.class */
public class SecT163R2Curve extends ECCurve.AbstractF2m {
    private static final int SECT163R2_DEFAULT_COORDS = 6;
    private static final ECFieldElement[] SECT163R2_AFFINE_ZS = {new SecT163FieldElement(ECConstants.ONE)};
    protected SecT163R2Point infinity;

    public SecT163R2Curve() {
        super(Opcode.IF_ICMPGT, 3, 6, 7);
        this.infinity = new SecT163R2Point(this, null, null);
        this.f661a = fromBigInteger(BigInteger.valueOf(1L));
        this.f662b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("020A601907B8C953CA1481EB10512F78744A3205FD")));
        this.order = new BigInteger(1, Hex.decodeStrict("040000000000000000000292FE77E70C12A4234C33"));
        this.cofactor = BigInteger.valueOf(2L);
        this.coord = 6;
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    protected ECCurve cloneCurve() {
        return new SecT163R2Curve();
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public boolean supportsCoordinateSystem(int i) {
        switch (i) {
            case 6:
                return true;
            default:
                return false;
        }
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public int getFieldSize() {
        return Opcode.IF_ICMPGT;
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECFieldElement fromBigInteger(BigInteger bigInteger) {
        return new SecT163FieldElement(bigInteger);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return new SecT163R2Point(this, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        return new SecT163R2Point(this, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECPoint getInfinity() {
        return this.infinity;
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve.AbstractF2m
    public boolean isKoblitz() {
        return false;
    }

    public int getM() {
        return Opcode.IF_ICMPGT;
    }

    public boolean isTrinomial() {
        return false;
    }

    public int getK1() {
        return 3;
    }

    public int getK2() {
        return 6;
    }

    public int getK3() {
        return 7;
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] eCPointArr, int i, final int i2) {
        final long[] jArr = new long[i2 * 3 * 2];
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            ECPoint eCPoint = eCPointArr[i + i4];
            Nat192.copy64(((SecT163FieldElement) eCPoint.getRawXCoord()).f753x, 0, jArr, i3);
            int i5 = i3 + 3;
            Nat192.copy64(((SecT163FieldElement) eCPoint.getRawYCoord()).f753x, 0, jArr, i5);
            i3 = i5 + 3;
        }
        return new AbstractECLookupTable() { // from class: org.bouncycastle.math.ec.custom.sec.SecT163R2Curve.1
            @Override // org.bouncycastle.math.p010ec.ECLookupTable
            public int getSize() {
                return i2;
            }

            @Override // org.bouncycastle.math.p010ec.ECLookupTable
            public ECPoint lookup(int i6) {
                long[] create64 = Nat192.create64();
                long[] create642 = Nat192.create64();
                int i7 = 0;
                for (int i8 = 0; i8 < i2; i8++) {
                    long j = ((i8 ^ i6) - 1) >> 31;
                    for (int i9 = 0; i9 < 3; i9++) {
                        int i10 = i9;
                        create64[i10] = create64[i10] ^ (jArr[i7 + i9] & j);
                        int i11 = i9;
                        create642[i11] = create642[i11] ^ (jArr[(i7 + 3) + i9] & j);
                    }
                    i7 += 6;
                }
                return createPoint(create64, create642);
            }

            @Override // org.bouncycastle.math.p010ec.AbstractECLookupTable, org.bouncycastle.math.p010ec.ECLookupTable
            public ECPoint lookupVar(int i6) {
                long[] create64 = Nat192.create64();
                long[] create642 = Nat192.create64();
                int i7 = i6 * 3 * 2;
                for (int i8 = 0; i8 < 3; i8++) {
                    create64[i8] = jArr[i7 + i8];
                    create642[i8] = jArr[i7 + 3 + i8];
                }
                return createPoint(create64, create642);
            }

            private ECPoint createPoint(long[] jArr2, long[] jArr3) {
                return SecT163R2Curve.this.createRawPoint(new SecT163FieldElement(jArr2), new SecT163FieldElement(jArr3), SecT163R2Curve.SECT163R2_AFFINE_ZS);
            }
        };
    }
}