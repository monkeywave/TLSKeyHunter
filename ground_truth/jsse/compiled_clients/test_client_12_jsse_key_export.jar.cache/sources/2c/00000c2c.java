package org.bouncycastle.math.p010ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Random;
import org.bouncycastle.math.field.FiniteField;
import org.bouncycastle.math.field.FiniteFields;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.p010ec.endo.ECEndomorphism;
import org.bouncycastle.math.p010ec.endo.GLVEndomorphism;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;

/* renamed from: org.bouncycastle.math.ec.ECCurve */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECCurve.class */
public abstract class ECCurve {
    public static final int COORD_AFFINE = 0;
    public static final int COORD_HOMOGENEOUS = 1;
    public static final int COORD_JACOBIAN = 2;
    public static final int COORD_JACOBIAN_CHUDNOVSKY = 3;
    public static final int COORD_JACOBIAN_MODIFIED = 4;
    public static final int COORD_LAMBDA_AFFINE = 5;
    public static final int COORD_LAMBDA_PROJECTIVE = 6;
    public static final int COORD_SKEWED = 7;
    protected FiniteField field;

    /* renamed from: a */
    protected ECFieldElement f661a;

    /* renamed from: b */
    protected ECFieldElement f662b;
    protected BigInteger order;
    protected BigInteger cofactor;
    protected int coord = 0;
    protected ECEndomorphism endomorphism = null;
    protected ECMultiplier multiplier = null;

    /* renamed from: org.bouncycastle.math.ec.ECCurve$AbstractF2m */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECCurve$AbstractF2m.class */
    public static abstract class AbstractF2m extends ECCurve {

        /* renamed from: si */
        private BigInteger[] f663si;

        public static BigInteger inverse(int i, int[] iArr, BigInteger bigInteger) {
            return new LongArray(bigInteger).modInverse(i, iArr).toBigInteger();
        }

        private static FiniteField buildField(int i, int i2, int i3, int i4) {
            if (i2 == 0) {
                throw new IllegalArgumentException("k1 must be > 0");
            }
            if (i3 == 0) {
                if (i4 != 0) {
                    throw new IllegalArgumentException("k3 must be 0 if k2 == 0");
                }
                return FiniteFields.getBinaryExtensionField(new int[]{0, i2, i});
            } else if (i3 <= i2) {
                throw new IllegalArgumentException("k2 must be > k1");
            } else {
                if (i4 <= i3) {
                    throw new IllegalArgumentException("k3 must be > k2");
                }
                return FiniteFields.getBinaryExtensionField(new int[]{0, i2, i3, i4, i});
            }
        }

        /* JADX INFO: Access modifiers changed from: protected */
        public AbstractF2m(int i, int i2, int i3, int i4) {
            super(buildField(i, i2, i3, i4));
            this.f663si = null;
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public ECPoint createPoint(BigInteger bigInteger, BigInteger bigInteger2) {
            ECFieldElement fromBigInteger = fromBigInteger(bigInteger);
            ECFieldElement fromBigInteger2 = fromBigInteger(bigInteger2);
            switch (getCoordinateSystem()) {
                case 5:
                case 6:
                    if (!fromBigInteger.isZero()) {
                        fromBigInteger2 = fromBigInteger2.divide(fromBigInteger).add(fromBigInteger);
                        break;
                    } else if (!fromBigInteger2.square().equals(getB())) {
                        throw new IllegalArgumentException();
                    }
                    break;
            }
            return createRawPoint(fromBigInteger, fromBigInteger2);
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public boolean isValidFieldElement(BigInteger bigInteger) {
            return bigInteger != null && bigInteger.signum() >= 0 && bigInteger.bitLength() <= getFieldSize();
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public ECFieldElement randomFieldElement(SecureRandom secureRandom) {
            return fromBigInteger(BigIntegers.createRandomBigInteger(getFieldSize(), secureRandom));
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public ECFieldElement randomFieldElementMult(SecureRandom secureRandom) {
            int fieldSize = getFieldSize();
            return fromBigInteger(implRandomFieldElementMult(secureRandom, fieldSize)).multiply(fromBigInteger(implRandomFieldElementMult(secureRandom, fieldSize)));
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        protected ECPoint decompressPoint(int i, BigInteger bigInteger) {
            ECFieldElement fromBigInteger = fromBigInteger(bigInteger);
            ECFieldElement eCFieldElement = null;
            if (!fromBigInteger.isZero()) {
                ECFieldElement solveQuadraticEquation = solveQuadraticEquation(fromBigInteger.square().invert().multiply(getB()).add(getA()).add(fromBigInteger));
                if (solveQuadraticEquation != null) {
                    if (solveQuadraticEquation.testBitZero() != (i == 1)) {
                        solveQuadraticEquation = solveQuadraticEquation.addOne();
                    }
                    switch (getCoordinateSystem()) {
                        case 5:
                        case 6:
                            eCFieldElement = solveQuadraticEquation.add(fromBigInteger);
                            break;
                        default:
                            eCFieldElement = solveQuadraticEquation.multiply(fromBigInteger);
                            break;
                    }
                }
            } else {
                eCFieldElement = getB().sqrt();
            }
            if (eCFieldElement == null) {
                throw new IllegalArgumentException("Invalid point compression");
            }
            return createRawPoint(fromBigInteger, eCFieldElement);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        public ECFieldElement solveQuadraticEquation(ECFieldElement eCFieldElement) {
            ECFieldElement eCFieldElement2;
            ECFieldElement.AbstractF2m abstractF2m = (ECFieldElement.AbstractF2m) eCFieldElement;
            boolean hasFastTrace = abstractF2m.hasFastTrace();
            if (!hasFastTrace || 0 == abstractF2m.trace()) {
                int fieldSize = getFieldSize();
                if (0 != (fieldSize & 1)) {
                    ECFieldElement halfTrace = abstractF2m.halfTrace();
                    if (hasFastTrace || halfTrace.square().add(halfTrace).add(eCFieldElement).isZero()) {
                        return halfTrace;
                    }
                    return null;
                } else if (eCFieldElement.isZero()) {
                    return eCFieldElement;
                } else {
                    ECFieldElement fromBigInteger = fromBigInteger(ECConstants.ZERO);
                    Random random = new Random();
                    do {
                        ECFieldElement fromBigInteger2 = fromBigInteger(new BigInteger(fieldSize, random));
                        eCFieldElement2 = fromBigInteger;
                        ECFieldElement eCFieldElement3 = eCFieldElement;
                        for (int i = 1; i < fieldSize; i++) {
                            ECFieldElement square = eCFieldElement3.square();
                            eCFieldElement2 = eCFieldElement2.square().add(square.multiply(fromBigInteger2));
                            eCFieldElement3 = square.add(eCFieldElement);
                        }
                        if (!eCFieldElement3.isZero()) {
                            return null;
                        }
                    } while (eCFieldElement2.square().add(eCFieldElement2).isZero());
                    return eCFieldElement2;
                }
            }
            return null;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public synchronized BigInteger[] getSi() {
            if (this.f663si == null) {
                this.f663si = Tnaf.getSi(this);
            }
            return this.f663si;
        }

        public boolean isKoblitz() {
            return this.order != null && this.cofactor != null && this.f662b.isOne() && (this.f661a.isZero() || this.f661a.isOne());
        }

        private static BigInteger implRandomFieldElementMult(SecureRandom secureRandom, int i) {
            BigInteger createRandomBigInteger;
            do {
                createRandomBigInteger = BigIntegers.createRandomBigInteger(i, secureRandom);
            } while (createRandomBigInteger.signum() <= 0);
            return createRandomBigInteger;
        }
    }

    /* renamed from: org.bouncycastle.math.ec.ECCurve$AbstractFp */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECCurve$AbstractFp.class */
    public static abstract class AbstractFp extends ECCurve {
        /* JADX INFO: Access modifiers changed from: protected */
        public AbstractFp(BigInteger bigInteger) {
            super(FiniteFields.getPrimeField(bigInteger));
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public boolean isValidFieldElement(BigInteger bigInteger) {
            return bigInteger != null && bigInteger.signum() >= 0 && bigInteger.compareTo(getField().getCharacteristic()) < 0;
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public ECFieldElement randomFieldElement(SecureRandom secureRandom) {
            BigInteger characteristic = getField().getCharacteristic();
            return fromBigInteger(implRandomFieldElement(secureRandom, characteristic)).multiply(fromBigInteger(implRandomFieldElement(secureRandom, characteristic)));
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public ECFieldElement randomFieldElementMult(SecureRandom secureRandom) {
            BigInteger characteristic = getField().getCharacteristic();
            return fromBigInteger(implRandomFieldElementMult(secureRandom, characteristic)).multiply(fromBigInteger(implRandomFieldElementMult(secureRandom, characteristic)));
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        protected ECPoint decompressPoint(int i, BigInteger bigInteger) {
            ECFieldElement fromBigInteger = fromBigInteger(bigInteger);
            ECFieldElement sqrt = fromBigInteger.square().add(this.f661a).multiply(fromBigInteger).add(this.f662b).sqrt();
            if (sqrt == null) {
                throw new IllegalArgumentException("Invalid point compression");
            }
            if (sqrt.testBitZero() != (i == 1)) {
                sqrt = sqrt.negate();
            }
            return createRawPoint(fromBigInteger, sqrt);
        }

        private static BigInteger implRandomFieldElement(SecureRandom secureRandom, BigInteger bigInteger) {
            BigInteger createRandomBigInteger;
            do {
                createRandomBigInteger = BigIntegers.createRandomBigInteger(bigInteger.bitLength(), secureRandom);
            } while (createRandomBigInteger.compareTo(bigInteger) >= 0);
            return createRandomBigInteger;
        }

        private static BigInteger implRandomFieldElementMult(SecureRandom secureRandom, BigInteger bigInteger) {
            while (true) {
                BigInteger createRandomBigInteger = BigIntegers.createRandomBigInteger(bigInteger.bitLength(), secureRandom);
                if (createRandomBigInteger.signum() > 0 && createRandomBigInteger.compareTo(bigInteger) < 0) {
                    return createRandomBigInteger;
                }
            }
        }
    }

    /* renamed from: org.bouncycastle.math.ec.ECCurve$Config */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECCurve$Config.class */
    public class Config {
        protected int coord;
        protected ECEndomorphism endomorphism;
        protected ECMultiplier multiplier;

        Config(int i, ECEndomorphism eCEndomorphism, ECMultiplier eCMultiplier) {
            this.coord = i;
            this.endomorphism = eCEndomorphism;
            this.multiplier = eCMultiplier;
        }

        public Config setCoordinateSystem(int i) {
            this.coord = i;
            return this;
        }

        public Config setEndomorphism(ECEndomorphism eCEndomorphism) {
            this.endomorphism = eCEndomorphism;
            return this;
        }

        public Config setMultiplier(ECMultiplier eCMultiplier) {
            this.multiplier = eCMultiplier;
            return this;
        }

        public ECCurve create() {
            if (ECCurve.this.supportsCoordinateSystem(this.coord)) {
                ECCurve cloneCurve = ECCurve.this.cloneCurve();
                if (cloneCurve == ECCurve.this) {
                    throw new IllegalStateException("implementation returned current curve");
                }
                synchronized (cloneCurve) {
                    cloneCurve.coord = this.coord;
                    cloneCurve.endomorphism = this.endomorphism;
                    cloneCurve.multiplier = this.multiplier;
                }
                return cloneCurve;
            }
            throw new IllegalStateException("unsupported coordinate system");
        }
    }

    /* renamed from: org.bouncycastle.math.ec.ECCurve$F2m */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECCurve$F2m.class */
    public static class F2m extends AbstractF2m {
        private static final int F2M_DEFAULT_COORDS = 6;

        /* renamed from: m */
        private int f664m;

        /* renamed from: k1 */
        private int f665k1;

        /* renamed from: k2 */
        private int f666k2;

        /* renamed from: k3 */
        private int f667k3;
        private ECPoint.F2m infinity;

        public F2m(int i, int i2, BigInteger bigInteger, BigInteger bigInteger2) {
            this(i, i2, 0, 0, bigInteger, bigInteger2, (BigInteger) null, (BigInteger) null);
        }

        public F2m(int i, int i2, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
            this(i, i2, 0, 0, bigInteger, bigInteger2, bigInteger3, bigInteger4);
        }

        public F2m(int i, int i2, int i3, int i4, BigInteger bigInteger, BigInteger bigInteger2) {
            this(i, i2, i3, i4, bigInteger, bigInteger2, (BigInteger) null, (BigInteger) null);
        }

        public F2m(int i, int i2, int i3, int i4, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
            super(i, i2, i3, i4);
            this.f664m = i;
            this.f665k1 = i2;
            this.f666k2 = i3;
            this.f667k3 = i4;
            this.order = bigInteger3;
            this.cofactor = bigInteger4;
            this.infinity = new ECPoint.F2m(this, null, null);
            this.f661a = fromBigInteger(bigInteger);
            this.f662b = fromBigInteger(bigInteger2);
            this.coord = 6;
        }

        protected F2m(int i, int i2, int i3, int i4, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, BigInteger bigInteger, BigInteger bigInteger2) {
            super(i, i2, i3, i4);
            this.f664m = i;
            this.f665k1 = i2;
            this.f666k2 = i3;
            this.f667k3 = i4;
            this.order = bigInteger;
            this.cofactor = bigInteger2;
            this.infinity = new ECPoint.F2m(this, null, null);
            this.f661a = eCFieldElement;
            this.f662b = eCFieldElement2;
            this.coord = 6;
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        protected ECCurve cloneCurve() {
            return new F2m(this.f664m, this.f665k1, this.f666k2, this.f667k3, this.f661a, this.f662b, this.order, this.cofactor);
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public boolean supportsCoordinateSystem(int i) {
            switch (i) {
                case 0:
                case 1:
                case 6:
                    return true;
                default:
                    return false;
            }
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        protected ECMultiplier createDefaultMultiplier() {
            return isKoblitz() ? new WTauNafMultiplier() : super.createDefaultMultiplier();
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public int getFieldSize() {
            return this.f664m;
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public ECFieldElement fromBigInteger(BigInteger bigInteger) {
            return new ECFieldElement.F2m(this.f664m, this.f665k1, this.f666k2, this.f667k3, bigInteger);
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        protected ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            return new ECPoint.F2m(this, eCFieldElement, eCFieldElement2);
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        protected ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
            return new ECPoint.F2m(this, eCFieldElement, eCFieldElement2, eCFieldElementArr);
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public ECPoint getInfinity() {
            return this.infinity;
        }

        public int getM() {
            return this.f664m;
        }

        public boolean isTrinomial() {
            return this.f666k2 == 0 && this.f667k3 == 0;
        }

        public int getK1() {
            return this.f665k1;
        }

        public int getK2() {
            return this.f666k2;
        }

        public int getK3() {
            return this.f667k3;
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public ECLookupTable createCacheSafeLookupTable(ECPoint[] eCPointArr, int i, final int i2) {
            final int i3 = (this.f664m + 63) >>> 6;
            final int[] iArr = isTrinomial() ? new int[]{this.f665k1} : new int[]{this.f665k1, this.f666k2, this.f667k3};
            final long[] jArr = new long[i2 * i3 * 2];
            int i4 = 0;
            for (int i5 = 0; i5 < i2; i5++) {
                ECPoint eCPoint = eCPointArr[i + i5];
                ((ECFieldElement.F2m) eCPoint.getRawXCoord()).f672x.copyTo(jArr, i4);
                int i6 = i4 + i3;
                ((ECFieldElement.F2m) eCPoint.getRawYCoord()).f672x.copyTo(jArr, i6);
                i4 = i6 + i3;
            }
            return new AbstractECLookupTable() { // from class: org.bouncycastle.math.ec.ECCurve.F2m.1
                @Override // org.bouncycastle.math.p010ec.ECLookupTable
                public int getSize() {
                    return i2;
                }

                @Override // org.bouncycastle.math.p010ec.ECLookupTable
                public ECPoint lookup(int i7) {
                    long[] create64 = Nat.create64(i3);
                    long[] create642 = Nat.create64(i3);
                    int i8 = 0;
                    for (int i9 = 0; i9 < i2; i9++) {
                        long j = ((i9 ^ i7) - 1) >> 31;
                        for (int i10 = 0; i10 < i3; i10++) {
                            int i11 = i10;
                            create64[i11] = create64[i11] ^ (jArr[i8 + i10] & j);
                            int i12 = i10;
                            create642[i12] = create642[i12] ^ (jArr[(i8 + i3) + i10] & j);
                        }
                        i8 += i3 * 2;
                    }
                    return createPoint(create64, create642);
                }

                @Override // org.bouncycastle.math.p010ec.AbstractECLookupTable, org.bouncycastle.math.p010ec.ECLookupTable
                public ECPoint lookupVar(int i7) {
                    long[] create64 = Nat.create64(i3);
                    long[] create642 = Nat.create64(i3);
                    int i8 = i7 * i3 * 2;
                    for (int i9 = 0; i9 < i3; i9++) {
                        create64[i9] = jArr[i8 + i9];
                        create642[i9] = jArr[i8 + i3 + i9];
                    }
                    return createPoint(create64, create642);
                }

                private ECPoint createPoint(long[] jArr2, long[] jArr3) {
                    return F2m.this.createRawPoint(new ECFieldElement.F2m(F2m.this.f664m, iArr, new LongArray(jArr2)), new ECFieldElement.F2m(F2m.this.f664m, iArr, new LongArray(jArr3)));
                }
            };
        }
    }

    /* renamed from: org.bouncycastle.math.ec.ECCurve$Fp */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECCurve$Fp.class */
    public static class C0277Fp extends AbstractFp {
        private static final int FP_DEFAULT_COORDS = 4;

        /* renamed from: q */
        BigInteger f668q;

        /* renamed from: r */
        BigInteger f669r;
        ECPoint.C0280Fp infinity;

        public C0277Fp(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
            this(bigInteger, bigInteger2, bigInteger3, null, null);
        }

        public C0277Fp(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4, BigInteger bigInteger5) {
            super(bigInteger);
            this.f668q = bigInteger;
            this.f669r = ECFieldElement.C0278Fp.calculateResidue(bigInteger);
            this.infinity = new ECPoint.C0280Fp(this, null, null);
            this.f661a = fromBigInteger(bigInteger2);
            this.f662b = fromBigInteger(bigInteger3);
            this.order = bigInteger4;
            this.cofactor = bigInteger5;
            this.coord = 4;
        }

        protected C0277Fp(BigInteger bigInteger, BigInteger bigInteger2, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, BigInteger bigInteger3, BigInteger bigInteger4) {
            super(bigInteger);
            this.f668q = bigInteger;
            this.f669r = bigInteger2;
            this.infinity = new ECPoint.C0280Fp(this, null, null);
            this.f661a = eCFieldElement;
            this.f662b = eCFieldElement2;
            this.order = bigInteger3;
            this.cofactor = bigInteger4;
            this.coord = 4;
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        protected ECCurve cloneCurve() {
            return new C0277Fp(this.f668q, this.f669r, this.f661a, this.f662b, this.order, this.cofactor);
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public boolean supportsCoordinateSystem(int i) {
            switch (i) {
                case 0:
                case 1:
                case 2:
                case 4:
                    return true;
                case 3:
                default:
                    return false;
            }
        }

        public BigInteger getQ() {
            return this.f668q;
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public int getFieldSize() {
            return this.f668q.bitLength();
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public ECFieldElement fromBigInteger(BigInteger bigInteger) {
            return new ECFieldElement.C0278Fp(this.f668q, this.f669r, bigInteger);
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        protected ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            return new ECPoint.C0280Fp(this, eCFieldElement, eCFieldElement2);
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        protected ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
            return new ECPoint.C0280Fp(this, eCFieldElement, eCFieldElement2, eCFieldElementArr);
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public ECPoint importPoint(ECPoint eCPoint) {
            if (this != eCPoint.getCurve() && getCoordinateSystem() == 2 && !eCPoint.isInfinity()) {
                switch (eCPoint.getCurve().getCoordinateSystem()) {
                    case 2:
                    case 3:
                    case 4:
                        return new ECPoint.C0280Fp(this, fromBigInteger(eCPoint.f676x.toBigInteger()), fromBigInteger(eCPoint.f677y.toBigInteger()), new ECFieldElement[]{fromBigInteger(eCPoint.f678zs[0].toBigInteger())});
                }
            }
            return super.importPoint(eCPoint);
        }

        @Override // org.bouncycastle.math.p010ec.ECCurve
        public ECPoint getInfinity() {
            return this.infinity;
        }
    }

    public static int[] getAllCoordinateSystems() {
        return new int[]{0, 1, 2, 3, 4, 5, 6, 7};
    }

    protected ECCurve(FiniteField finiteField) {
        this.field = finiteField;
    }

    public abstract int getFieldSize();

    public abstract ECFieldElement fromBigInteger(BigInteger bigInteger);

    public abstract boolean isValidFieldElement(BigInteger bigInteger);

    public abstract ECFieldElement randomFieldElement(SecureRandom secureRandom);

    public abstract ECFieldElement randomFieldElementMult(SecureRandom secureRandom);

    public synchronized Config configure() {
        return new Config(this.coord, this.endomorphism, this.multiplier);
    }

    public ECPoint validatePoint(BigInteger bigInteger, BigInteger bigInteger2) {
        ECPoint createPoint = createPoint(bigInteger, bigInteger2);
        if (createPoint.isValid()) {
            return createPoint;
        }
        throw new IllegalArgumentException("Invalid point coordinates");
    }

    public ECPoint createPoint(BigInteger bigInteger, BigInteger bigInteger2) {
        return createRawPoint(fromBigInteger(bigInteger), fromBigInteger(bigInteger2));
    }

    protected abstract ECCurve cloneCurve();

    /* JADX INFO: Access modifiers changed from: protected */
    public abstract ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2);

    /* JADX INFO: Access modifiers changed from: protected */
    public abstract ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr);

    protected ECMultiplier createDefaultMultiplier() {
        return this.endomorphism instanceof GLVEndomorphism ? new GLVMultiplier(this, (GLVEndomorphism) this.endomorphism) : new WNafL2RMultiplier();
    }

    public boolean supportsCoordinateSystem(int i) {
        return i == 0;
    }

    public PreCompInfo getPreCompInfo(ECPoint eCPoint, String str) {
        Hashtable hashtable;
        PreCompInfo preCompInfo;
        checkPoint(eCPoint);
        synchronized (eCPoint) {
            hashtable = eCPoint.preCompTable;
        }
        if (null == hashtable) {
            return null;
        }
        synchronized (hashtable) {
            preCompInfo = (PreCompInfo) hashtable.get(str);
        }
        return preCompInfo;
    }

    public PreCompInfo precompute(ECPoint eCPoint, String str, PreCompCallback preCompCallback) {
        Hashtable hashtable;
        PreCompInfo precompute;
        checkPoint(eCPoint);
        synchronized (eCPoint) {
            hashtable = eCPoint.preCompTable;
            if (null == hashtable) {
                Hashtable hashtable2 = new Hashtable(4);
                hashtable = hashtable2;
                eCPoint.preCompTable = hashtable2;
            }
        }
        synchronized (hashtable) {
            PreCompInfo preCompInfo = (PreCompInfo) hashtable.get(str);
            precompute = preCompCallback.precompute(preCompInfo);
            if (precompute != preCompInfo) {
                hashtable.put(str, precompute);
            }
        }
        return precompute;
    }

    public ECPoint importPoint(ECPoint eCPoint) {
        if (this == eCPoint.getCurve()) {
            return eCPoint;
        }
        if (eCPoint.isInfinity()) {
            return getInfinity();
        }
        ECPoint normalize = eCPoint.normalize();
        return createPoint(normalize.getXCoord().toBigInteger(), normalize.getYCoord().toBigInteger());
    }

    public void normalizeAll(ECPoint[] eCPointArr) {
        normalizeAll(eCPointArr, 0, eCPointArr.length, null);
    }

    public void normalizeAll(ECPoint[] eCPointArr, int i, int i2, ECFieldElement eCFieldElement) {
        checkPoints(eCPointArr, i, i2);
        switch (getCoordinateSystem()) {
            case 0:
            case 5:
                if (eCFieldElement != null) {
                    throw new IllegalArgumentException("'iso' not valid for affine coordinates");
                }
                return;
            default:
                ECFieldElement[] eCFieldElementArr = new ECFieldElement[i2];
                int[] iArr = new int[i2];
                int i3 = 0;
                for (int i4 = 0; i4 < i2; i4++) {
                    ECPoint eCPoint = eCPointArr[i + i4];
                    if (null != eCPoint && (eCFieldElement != null || !eCPoint.isNormalized())) {
                        eCFieldElementArr[i3] = eCPoint.getZCoord(0);
                        int i5 = i3;
                        i3++;
                        iArr[i5] = i + i4;
                    }
                }
                if (i3 == 0) {
                    return;
                }
                ECAlgorithms.montgomeryTrick(eCFieldElementArr, 0, i3, eCFieldElement);
                for (int i6 = 0; i6 < i3; i6++) {
                    int i7 = iArr[i6];
                    eCPointArr[i7] = eCPointArr[i7].normalize(eCFieldElementArr[i6]);
                }
                return;
        }
    }

    public abstract ECPoint getInfinity();

    public FiniteField getField() {
        return this.field;
    }

    public ECFieldElement getA() {
        return this.f661a;
    }

    public ECFieldElement getB() {
        return this.f662b;
    }

    public BigInteger getOrder() {
        return this.order;
    }

    public BigInteger getCofactor() {
        return this.cofactor;
    }

    public int getCoordinateSystem() {
        return this.coord;
    }

    protected abstract ECPoint decompressPoint(int i, BigInteger bigInteger);

    public ECEndomorphism getEndomorphism() {
        return this.endomorphism;
    }

    public ECMultiplier getMultiplier() {
        if (this.multiplier == null) {
            this.multiplier = createDefaultMultiplier();
        }
        return this.multiplier;
    }

    public ECPoint decodePoint(byte[] bArr) {
        ECPoint validatePoint;
        int fieldSize = (getFieldSize() + 7) / 8;
        byte b = bArr[0];
        switch (b) {
            case 0:
                if (bArr.length == 1) {
                    validatePoint = getInfinity();
                    break;
                } else {
                    throw new IllegalArgumentException("Incorrect length for infinity encoding");
                }
            case 1:
            case 5:
            default:
                throw new IllegalArgumentException("Invalid point encoding 0x" + Integer.toString(b, 16));
            case 2:
            case 3:
                if (bArr.length != fieldSize + 1) {
                    throw new IllegalArgumentException("Incorrect length for compressed encoding");
                }
                validatePoint = decompressPoint(b & 1, BigIntegers.fromUnsignedByteArray(bArr, 1, fieldSize));
                if (!validatePoint.implIsValid(true, true)) {
                    throw new IllegalArgumentException("Invalid point");
                }
                break;
            case 4:
                if (bArr.length == (2 * fieldSize) + 1) {
                    validatePoint = validatePoint(BigIntegers.fromUnsignedByteArray(bArr, 1, fieldSize), BigIntegers.fromUnsignedByteArray(bArr, 1 + fieldSize, fieldSize));
                    break;
                } else {
                    throw new IllegalArgumentException("Incorrect length for uncompressed encoding");
                }
            case 6:
            case 7:
                if (bArr.length == (2 * fieldSize) + 1) {
                    BigInteger fromUnsignedByteArray = BigIntegers.fromUnsignedByteArray(bArr, 1, fieldSize);
                    BigInteger fromUnsignedByteArray2 = BigIntegers.fromUnsignedByteArray(bArr, 1 + fieldSize, fieldSize);
                    if (fromUnsignedByteArray2.testBit(0) == (b == 7)) {
                        validatePoint = validatePoint(fromUnsignedByteArray, fromUnsignedByteArray2);
                        break;
                    } else {
                        throw new IllegalArgumentException("Inconsistent Y coordinate in hybrid encoding");
                    }
                } else {
                    throw new IllegalArgumentException("Incorrect length for hybrid encoding");
                }
        }
        if (b == 0 || !validatePoint.isInfinity()) {
            return validatePoint;
        }
        throw new IllegalArgumentException("Invalid infinity encoding");
    }

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] eCPointArr, int i, final int i2) {
        final int fieldSize = (getFieldSize() + 7) >>> 3;
        final byte[] bArr = new byte[i2 * fieldSize * 2];
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            ECPoint eCPoint = eCPointArr[i + i4];
            byte[] byteArray = eCPoint.getRawXCoord().toBigInteger().toByteArray();
            byte[] byteArray2 = eCPoint.getRawYCoord().toBigInteger().toByteArray();
            int i5 = byteArray.length > fieldSize ? 1 : 0;
            int length = byteArray.length - i5;
            int i6 = byteArray2.length > fieldSize ? 1 : 0;
            int length2 = byteArray2.length - i6;
            System.arraycopy(byteArray, i5, bArr, (i3 + fieldSize) - length, length);
            int i7 = i3 + fieldSize;
            System.arraycopy(byteArray2, i6, bArr, (i7 + fieldSize) - length2, length2);
            i3 = i7 + fieldSize;
        }
        return new AbstractECLookupTable() { // from class: org.bouncycastle.math.ec.ECCurve.1
            @Override // org.bouncycastle.math.p010ec.ECLookupTable
            public int getSize() {
                return i2;
            }

            @Override // org.bouncycastle.math.p010ec.ECLookupTable
            public ECPoint lookup(int i8) {
                byte[] bArr2 = new byte[fieldSize];
                byte[] bArr3 = new byte[fieldSize];
                int i9 = 0;
                for (int i10 = 0; i10 < i2; i10++) {
                    int i11 = ((i10 ^ i8) - 1) >> 31;
                    for (int i12 = 0; i12 < fieldSize; i12++) {
                        int i13 = i12;
                        bArr2[i13] = (byte) (bArr2[i13] ^ (bArr[i9 + i12] & i11));
                        int i14 = i12;
                        bArr3[i14] = (byte) (bArr3[i14] ^ (bArr[(i9 + fieldSize) + i12] & i11));
                    }
                    i9 += fieldSize * 2;
                }
                return createPoint(bArr2, bArr3);
            }

            @Override // org.bouncycastle.math.p010ec.AbstractECLookupTable, org.bouncycastle.math.p010ec.ECLookupTable
            public ECPoint lookupVar(int i8) {
                byte[] bArr2 = new byte[fieldSize];
                byte[] bArr3 = new byte[fieldSize];
                int i9 = i8 * fieldSize * 2;
                for (int i10 = 0; i10 < fieldSize; i10++) {
                    bArr2[i10] = bArr[i9 + i10];
                    bArr3[i10] = bArr[i9 + fieldSize + i10];
                }
                return createPoint(bArr2, bArr3);
            }

            private ECPoint createPoint(byte[] bArr2, byte[] bArr3) {
                return ECCurve.this.createRawPoint(ECCurve.this.fromBigInteger(new BigInteger(1, bArr2)), ECCurve.this.fromBigInteger(new BigInteger(1, bArr3)));
            }
        };
    }

    protected void checkPoint(ECPoint eCPoint) {
        if (null == eCPoint || this != eCPoint.getCurve()) {
            throw new IllegalArgumentException("'point' must be non-null and on this curve");
        }
    }

    protected void checkPoints(ECPoint[] eCPointArr) {
        checkPoints(eCPointArr, 0, eCPointArr.length);
    }

    protected void checkPoints(ECPoint[] eCPointArr, int i, int i2) {
        if (eCPointArr == null) {
            throw new IllegalArgumentException("'points' cannot be null");
        }
        if (i < 0 || i2 < 0 || i > eCPointArr.length - i2) {
            throw new IllegalArgumentException("invalid range specified for 'points'");
        }
        for (int i3 = 0; i3 < i2; i3++) {
            ECPoint eCPoint = eCPointArr[i + i3];
            if (null != eCPoint && this != eCPoint.getCurve()) {
                throw new IllegalArgumentException("'points' entries must be null or on this curve");
            }
        }
    }

    public boolean equals(ECCurve eCCurve) {
        return this == eCCurve || (null != eCCurve && getField().equals(eCCurve.getField()) && getA().toBigInteger().equals(eCCurve.getA().toBigInteger()) && getB().toBigInteger().equals(eCCurve.getB().toBigInteger()));
    }

    public boolean equals(Object obj) {
        return this == obj || ((obj instanceof ECCurve) && equals((ECCurve) obj));
    }

    public int hashCode() {
        return (getField().hashCode() ^ Integers.rotateLeft(getA().toBigInteger().hashCode(), 8)) ^ Integers.rotateLeft(getB().toBigInteger().hashCode(), 16);
    }
}