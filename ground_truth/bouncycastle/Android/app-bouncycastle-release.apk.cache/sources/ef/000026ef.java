package org.bouncycastle.math.p016ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Random;
import java.util.Set;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.Primes;
import org.bouncycastle.math.field.FiniteField;
import org.bouncycastle.math.field.FiniteFields;
import org.bouncycastle.math.p016ec.ECFieldElement;
import org.bouncycastle.math.p016ec.ECPoint;
import org.bouncycastle.math.p016ec.endo.ECEndomorphism;
import org.bouncycastle.math.p016ec.endo.GLVEndomorphism;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Properties;

/* renamed from: org.bouncycastle.math.ec.ECCurve */
/* loaded from: classes2.dex */
public abstract class ECCurve {
    public static final int COORD_AFFINE = 0;
    public static final int COORD_HOMOGENEOUS = 1;
    public static final int COORD_JACOBIAN = 2;
    public static final int COORD_JACOBIAN_CHUDNOVSKY = 3;
    public static final int COORD_JACOBIAN_MODIFIED = 4;
    public static final int COORD_LAMBDA_AFFINE = 5;
    public static final int COORD_LAMBDA_PROJECTIVE = 6;
    public static final int COORD_SKEWED = 7;

    /* renamed from: a */
    protected ECFieldElement f1000a;

    /* renamed from: b */
    protected ECFieldElement f1001b;
    protected BigInteger cofactor;
    protected FiniteField field;
    protected BigInteger order;
    protected int coord = 0;
    protected ECEndomorphism endomorphism = null;
    protected ECMultiplier multiplier = null;

    /* renamed from: org.bouncycastle.math.ec.ECCurve$AbstractF2m */
    /* loaded from: classes2.dex */
    public static abstract class AbstractF2m extends ECCurve {

        /* renamed from: si */
        private BigInteger[] f1002si;

        /* JADX INFO: Access modifiers changed from: protected */
        public AbstractF2m(int i, int i2, int i3, int i4) {
            super(buildField(i, i2, i3, i4));
            this.f1002si = null;
            if (Properties.isOverrideSet("org.bouncycastle.ec.disable")) {
                throw new UnsupportedOperationException("F2M disabled by \"org.bouncycastle.ec.disable\"");
            }
            if (Properties.isOverrideSet("org.bouncycastle.ec.disable_f2m")) {
                throw new UnsupportedOperationException("F2M disabled by \"org.bouncycastle.ec.disable_f2m\"");
            }
        }

        private static FiniteField buildField(int i, int i2, int i3, int i4) {
            if (i <= Properties.asInteger("org.bouncycastle.ec.max_f2m_field_size", 1142)) {
                return FiniteFields.getBinaryExtensionField((i3 | i4) == 0 ? new int[]{0, i2, i} : new int[]{0, i2, i3, i4, i});
            }
            throw new IllegalArgumentException("field size out of range: " + i);
        }

        private static BigInteger implRandomFieldElementMult(SecureRandom secureRandom, int i) {
            BigInteger createRandomBigInteger;
            do {
                createRandomBigInteger = BigIntegers.createRandomBigInteger(i, secureRandom);
            } while (createRandomBigInteger.signum() <= 0);
            return createRandomBigInteger;
        }

        public static BigInteger inverse(int i, int[] iArr, BigInteger bigInteger) {
            return new LongArray(bigInteger).modInverse(i, iArr).toBigInteger();
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public ECPoint createPoint(BigInteger bigInteger, BigInteger bigInteger2) {
            ECFieldElement fromBigInteger = fromBigInteger(bigInteger);
            ECFieldElement fromBigInteger2 = fromBigInteger(bigInteger2);
            int coordinateSystem = getCoordinateSystem();
            if (coordinateSystem == 5 || coordinateSystem == 6) {
                if (!fromBigInteger.isZero()) {
                    fromBigInteger2 = fromBigInteger2.divide(fromBigInteger).add(fromBigInteger);
                } else if (!fromBigInteger2.square().equals(getB())) {
                    throw new IllegalArgumentException();
                }
            }
            return createRawPoint(fromBigInteger, fromBigInteger2);
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        protected ECPoint decompressPoint(int i, BigInteger bigInteger) {
            ECFieldElement eCFieldElement;
            ECFieldElement fromBigInteger = fromBigInteger(bigInteger);
            if (fromBigInteger.isZero()) {
                eCFieldElement = getB().sqrt();
            } else {
                ECFieldElement solveQuadraticEquation = solveQuadraticEquation(fromBigInteger.square().invert().multiply(getB()).add(getA()).add(fromBigInteger));
                if (solveQuadraticEquation != null) {
                    if (solveQuadraticEquation.testBitZero() != (i == 1)) {
                        solveQuadraticEquation = solveQuadraticEquation.addOne();
                    }
                    int coordinateSystem = getCoordinateSystem();
                    eCFieldElement = (coordinateSystem == 5 || coordinateSystem == 6) ? solveQuadraticEquation.add(fromBigInteger) : solveQuadraticEquation.multiply(fromBigInteger);
                } else {
                    eCFieldElement = null;
                }
            }
            if (eCFieldElement != null) {
                return createRawPoint(fromBigInteger, eCFieldElement);
            }
            throw new IllegalArgumentException("Invalid point compression");
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public synchronized BigInteger[] getSi() {
            if (this.f1002si == null) {
                this.f1002si = Tnaf.getSi(this);
            }
            return this.f1002si;
        }

        public boolean isKoblitz() {
            return this.order != null && this.cofactor != null && this.f1001b.isOne() && (this.f1000a.isZero() || this.f1000a.isOne());
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public boolean isValidFieldElement(BigInteger bigInteger) {
            return bigInteger != null && bigInteger.signum() >= 0 && bigInteger.bitLength() <= getFieldSize();
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public ECFieldElement randomFieldElement(SecureRandom secureRandom) {
            return fromBigInteger(BigIntegers.createRandomBigInteger(getFieldSize(), secureRandom));
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public ECFieldElement randomFieldElementMult(SecureRandom secureRandom) {
            int fieldSize = getFieldSize();
            return fromBigInteger(implRandomFieldElementMult(secureRandom, fieldSize)).multiply(fromBigInteger(implRandomFieldElementMult(secureRandom, fieldSize)));
        }

        /* JADX INFO: Access modifiers changed from: protected */
        public ECFieldElement solveQuadraticEquation(ECFieldElement eCFieldElement) {
            ECFieldElement eCFieldElement2;
            ECFieldElement.AbstractF2m abstractF2m = (ECFieldElement.AbstractF2m) eCFieldElement;
            boolean hasFastTrace = abstractF2m.hasFastTrace();
            if (!hasFastTrace || abstractF2m.trace() == 0) {
                int fieldSize = getFieldSize();
                if ((fieldSize & 1) != 0) {
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
                        ECFieldElement eCFieldElement3 = eCFieldElement;
                        eCFieldElement2 = fromBigInteger;
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
    }

    /* renamed from: org.bouncycastle.math.ec.ECCurve$AbstractFp */
    /* loaded from: classes2.dex */
    public static abstract class AbstractFp extends ECCurve {
        /* JADX INFO: Access modifiers changed from: protected */
        public AbstractFp(BigInteger bigInteger) {
            super(FiniteFields.getPrimeField(bigInteger));
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

        @Override // org.bouncycastle.math.p016ec.ECCurve
        protected ECPoint decompressPoint(int i, BigInteger bigInteger) {
            ECFieldElement fromBigInteger = fromBigInteger(bigInteger);
            ECFieldElement sqrt = fromBigInteger.square().add(this.f1000a).multiply(fromBigInteger).add(this.f1001b).sqrt();
            if (sqrt != null) {
                if (sqrt.testBitZero() != (i == 1)) {
                    sqrt = sqrt.negate();
                }
                return createRawPoint(fromBigInteger, sqrt);
            }
            throw new IllegalArgumentException("Invalid point compression");
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public boolean isValidFieldElement(BigInteger bigInteger) {
            return bigInteger != null && bigInteger.signum() >= 0 && bigInteger.compareTo(getField().getCharacteristic()) < 0;
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public ECFieldElement randomFieldElement(SecureRandom secureRandom) {
            BigInteger characteristic = getField().getCharacteristic();
            return fromBigInteger(implRandomFieldElement(secureRandom, characteristic)).multiply(fromBigInteger(implRandomFieldElement(secureRandom, characteristic)));
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public ECFieldElement randomFieldElementMult(SecureRandom secureRandom) {
            BigInteger characteristic = getField().getCharacteristic();
            return fromBigInteger(implRandomFieldElementMult(secureRandom, characteristic)).multiply(fromBigInteger(implRandomFieldElementMult(secureRandom, characteristic)));
        }
    }

    /* renamed from: org.bouncycastle.math.ec.ECCurve$Config */
    /* loaded from: classes2.dex */
    public class Config {
        protected int coord;
        protected ECEndomorphism endomorphism;
        protected ECMultiplier multiplier;

        Config(int i, ECEndomorphism eCEndomorphism, ECMultiplier eCMultiplier) {
            this.coord = i;
            this.endomorphism = eCEndomorphism;
            this.multiplier = eCMultiplier;
        }

        public ECCurve create() {
            if (ECCurve.this.supportsCoordinateSystem(this.coord)) {
                ECCurve cloneCurve = ECCurve.this.cloneCurve();
                if (cloneCurve != ECCurve.this) {
                    synchronized (cloneCurve) {
                        cloneCurve.coord = this.coord;
                        cloneCurve.endomorphism = this.endomorphism;
                        cloneCurve.multiplier = this.multiplier;
                    }
                    return cloneCurve;
                }
                throw new IllegalStateException("implementation returned current curve");
            }
            throw new IllegalStateException("unsupported coordinate system");
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
    }

    /* renamed from: org.bouncycastle.math.ec.ECCurve$F2m */
    /* loaded from: classes2.dex */
    public static class F2m extends AbstractF2m {
        private static final int F2M_DEFAULT_COORDS = 6;
        private ECPoint.F2m infinity;

        /* renamed from: k1 */
        private int f1003k1;

        /* renamed from: k2 */
        private int f1004k2;

        /* renamed from: k3 */
        private int f1005k3;

        /* renamed from: m */
        private int f1006m;

        public F2m(int i, int i2, int i3, int i4, BigInteger bigInteger, BigInteger bigInteger2) {
            this(i, i2, i3, i4, bigInteger, bigInteger2, (BigInteger) null, (BigInteger) null);
        }

        public F2m(int i, int i2, int i3, int i4, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
            super(i, i2, i3, i4);
            this.f1006m = i;
            this.f1003k1 = i2;
            this.f1004k2 = i3;
            this.f1005k3 = i4;
            this.order = bigInteger3;
            this.cofactor = bigInteger4;
            this.infinity = new ECPoint.F2m(this, null, null);
            this.f1000a = fromBigInteger(bigInteger);
            this.f1001b = fromBigInteger(bigInteger2);
            this.coord = 6;
        }

        protected F2m(int i, int i2, int i3, int i4, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, BigInteger bigInteger, BigInteger bigInteger2) {
            super(i, i2, i3, i4);
            this.f1006m = i;
            this.f1003k1 = i2;
            this.f1004k2 = i3;
            this.f1005k3 = i4;
            this.order = bigInteger;
            this.cofactor = bigInteger2;
            this.infinity = new ECPoint.F2m(this, null, null);
            this.f1000a = eCFieldElement;
            this.f1001b = eCFieldElement2;
            this.coord = 6;
        }

        public F2m(int i, int i2, BigInteger bigInteger, BigInteger bigInteger2) {
            this(i, i2, 0, 0, bigInteger, bigInteger2, (BigInteger) null, (BigInteger) null);
        }

        public F2m(int i, int i2, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
            this(i, i2, 0, 0, bigInteger, bigInteger2, bigInteger3, bigInteger4);
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        protected ECCurve cloneCurve() {
            return new F2m(this.f1006m, this.f1003k1, this.f1004k2, this.f1005k3, this.f1000a, this.f1001b, this.order, this.cofactor);
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public ECLookupTable createCacheSafeLookupTable(ECPoint[] eCPointArr, int i, final int i2) {
            final int i3 = (this.f1006m + 63) >>> 6;
            final int[] iArr = isTrinomial() ? new int[]{this.f1003k1} : new int[]{this.f1003k1, this.f1004k2, this.f1005k3};
            final long[] jArr = new long[i2 * i3 * 2];
            int i4 = 0;
            for (int i5 = 0; i5 < i2; i5++) {
                ECPoint eCPoint = eCPointArr[i + i5];
                ((ECFieldElement.F2m) eCPoint.getRawXCoord()).f1011x.copyTo(jArr, i4);
                int i6 = i4 + i3;
                ((ECFieldElement.F2m) eCPoint.getRawYCoord()).f1011x.copyTo(jArr, i6);
                i4 = i6 + i3;
            }
            return new AbstractECLookupTable() { // from class: org.bouncycastle.math.ec.ECCurve.F2m.1
                private ECPoint createPoint(long[] jArr2, long[] jArr3) {
                    return F2m.this.createRawPoint(new ECFieldElement.F2m(F2m.this.f1006m, iArr, new LongArray(jArr2)), new ECFieldElement.F2m(F2m.this.f1006m, iArr, new LongArray(jArr3)));
                }

                @Override // org.bouncycastle.math.p016ec.ECLookupTable
                public int getSize() {
                    return i2;
                }

                @Override // org.bouncycastle.math.p016ec.ECLookupTable
                public ECPoint lookup(int i7) {
                    int i8;
                    long[] create64 = Nat.create64(i3);
                    long[] create642 = Nat.create64(i3);
                    int i9 = 0;
                    for (int i10 = 0; i10 < i2; i10++) {
                        long j = ((i10 ^ i7) - 1) >> 31;
                        int i11 = 0;
                        while (true) {
                            i8 = i3;
                            if (i11 < i8) {
                                long j2 = create64[i11];
                                long[] jArr2 = jArr;
                                create64[i11] = j2 ^ (jArr2[i9 + i11] & j);
                                create642[i11] = create642[i11] ^ (jArr2[(i8 + i9) + i11] & j);
                                i11++;
                            }
                        }
                        i9 += i8 * 2;
                    }
                    return createPoint(create64, create642);
                }

                @Override // org.bouncycastle.math.p016ec.AbstractECLookupTable, org.bouncycastle.math.p016ec.ECLookupTable
                public ECPoint lookupVar(int i7) {
                    long[] create64 = Nat.create64(i3);
                    long[] create642 = Nat.create64(i3);
                    int i8 = i7 * i3 * 2;
                    int i9 = 0;
                    while (true) {
                        int i10 = i3;
                        if (i9 >= i10) {
                            return createPoint(create64, create642);
                        }
                        long[] jArr2 = jArr;
                        create64[i9] = jArr2[i8 + i9];
                        create642[i9] = jArr2[i10 + i8 + i9];
                        i9++;
                    }
                }
            };
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        protected ECMultiplier createDefaultMultiplier() {
            return isKoblitz() ? new WTauNafMultiplier() : super.createDefaultMultiplier();
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        protected ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            return new ECPoint.F2m(this, eCFieldElement, eCFieldElement2);
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        protected ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
            return new ECPoint.F2m(this, eCFieldElement, eCFieldElement2, eCFieldElementArr);
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public ECFieldElement fromBigInteger(BigInteger bigInteger) {
            if (bigInteger == null || bigInteger.signum() < 0 || bigInteger.bitLength() > this.f1006m) {
                throw new IllegalArgumentException("x value invalid in F2m field element");
            }
            int i = this.f1004k2;
            int i2 = this.f1005k3;
            return new ECFieldElement.F2m(this.f1006m, (i | i2) == 0 ? new int[]{this.f1003k1} : new int[]{this.f1003k1, i, i2}, new LongArray(bigInteger));
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public int getFieldSize() {
            return this.f1006m;
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public ECPoint getInfinity() {
            return this.infinity;
        }

        public int getK1() {
            return this.f1003k1;
        }

        public int getK2() {
            return this.f1004k2;
        }

        public int getK3() {
            return this.f1005k3;
        }

        public int getM() {
            return this.f1006m;
        }

        public boolean isTrinomial() {
            return this.f1004k2 == 0 && this.f1005k3 == 0;
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public boolean supportsCoordinateSystem(int i) {
            return i == 0 || i == 1 || i == 6;
        }
    }

    /* renamed from: org.bouncycastle.math.ec.ECCurve$Fp */
    /* loaded from: classes2.dex */
    public static class C1333Fp extends AbstractFp {
        private static final int FP_DEFAULT_COORDS = 4;
        private static final Set<BigInteger> knownQs = Collections.synchronizedSet(new HashSet());
        private static final BigIntegers.Cache validatedQs = new BigIntegers.Cache();
        ECPoint.C1336Fp infinity;

        /* renamed from: q */
        BigInteger f1007q;

        /* renamed from: r */
        BigInteger f1008r;

        public C1333Fp(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
            this(bigInteger, bigInteger2, bigInteger3, null, null);
        }

        public C1333Fp(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4, BigInteger bigInteger5) {
            this(bigInteger, bigInteger2, bigInteger3, bigInteger4, bigInteger5, false);
        }

        public C1333Fp(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4, BigInteger bigInteger5, boolean z) {
            super(bigInteger);
            if (z) {
                this.f1007q = bigInteger;
                knownQs.add(bigInteger);
            } else {
                if (!knownQs.contains(bigInteger)) {
                    BigIntegers.Cache cache = validatedQs;
                    if (!cache.contains(bigInteger)) {
                        int asInteger = Properties.asInteger("org.bouncycastle.ec.fp_max_size", 1042);
                        int asInteger2 = Properties.asInteger("org.bouncycastle.ec.fp_certainty", 100);
                        int bitLength = bigInteger.bitLength();
                        if (asInteger < bitLength) {
                            throw new IllegalArgumentException("Fp q value out of range");
                        }
                        if (Primes.hasAnySmallFactors(bigInteger) || !Primes.isMRProbablePrime(bigInteger, CryptoServicesRegistrar.getSecureRandom(), ECCurve.getNumberOfIterations(bitLength, asInteger2))) {
                            throw new IllegalArgumentException("Fp q value not prime");
                        }
                        cache.add(bigInteger);
                    }
                }
                this.f1007q = bigInteger;
            }
            this.f1008r = ECFieldElement.C1334Fp.calculateResidue(bigInteger);
            this.infinity = new ECPoint.C1336Fp(this, null, null);
            this.f1000a = fromBigInteger(bigInteger2);
            this.f1001b = fromBigInteger(bigInteger3);
            this.order = bigInteger4;
            this.cofactor = bigInteger5;
            this.coord = 4;
        }

        protected C1333Fp(BigInteger bigInteger, BigInteger bigInteger2, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, BigInteger bigInteger3, BigInteger bigInteger4) {
            super(bigInteger);
            this.f1007q = bigInteger;
            this.f1008r = bigInteger2;
            this.infinity = new ECPoint.C1336Fp(this, null, null);
            this.f1000a = eCFieldElement;
            this.f1001b = eCFieldElement2;
            this.order = bigInteger3;
            this.cofactor = bigInteger4;
            this.coord = 4;
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        protected ECCurve cloneCurve() {
            return new C1333Fp(this.f1007q, this.f1008r, this.f1000a, this.f1001b, this.order, this.cofactor);
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        protected ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            return new ECPoint.C1336Fp(this, eCFieldElement, eCFieldElement2);
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        protected ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
            return new ECPoint.C1336Fp(this, eCFieldElement, eCFieldElement2, eCFieldElementArr);
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public ECFieldElement fromBigInteger(BigInteger bigInteger) {
            if (bigInteger == null || bigInteger.signum() < 0 || bigInteger.compareTo(this.f1007q) >= 0) {
                throw new IllegalArgumentException("x value invalid for Fp field element");
            }
            return new ECFieldElement.C1334Fp(this.f1007q, this.f1008r, bigInteger);
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public int getFieldSize() {
            return this.f1007q.bitLength();
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public ECPoint getInfinity() {
            return this.infinity;
        }

        public BigInteger getQ() {
            return this.f1007q;
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public ECPoint importPoint(ECPoint eCPoint) {
            int coordinateSystem;
            return (this == eCPoint.getCurve() || getCoordinateSystem() != 2 || eCPoint.isInfinity() || !((coordinateSystem = eCPoint.getCurve().getCoordinateSystem()) == 2 || coordinateSystem == 3 || coordinateSystem == 4)) ? super.importPoint(eCPoint) : new ECPoint.C1336Fp(this, fromBigInteger(eCPoint.f1015x.toBigInteger()), fromBigInteger(eCPoint.f1016y.toBigInteger()), new ECFieldElement[]{fromBigInteger(eCPoint.f1017zs[0].toBigInteger())});
        }

        @Override // org.bouncycastle.math.p016ec.ECCurve
        public boolean supportsCoordinateSystem(int i) {
            return i == 0 || i == 1 || i == 2 || i == 4;
        }
    }

    protected ECCurve(FiniteField finiteField) {
        this.field = finiteField;
    }

    public static int[] getAllCoordinateSystems() {
        return new int[]{0, 1, 2, 3, 4, 5, 6, 7};
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int getNumberOfIterations(int i, int i2) {
        if (i >= 1536) {
            if (i2 <= 100) {
                return 3;
            }
            if (i2 <= 128) {
                return 4;
            }
            return 4 + ((i2 - 127) / 2);
        } else if (i >= 1024) {
            if (i2 <= 100) {
                return 4;
            }
            if (i2 <= 112) {
                return 5;
            }
            return ((i2 - 111) / 2) + 5;
        } else if (i < 512) {
            if (i2 <= 80) {
                return 40;
            }
            return 40 + ((i2 - 79) / 2);
        } else if (i2 <= 80) {
            return 5;
        } else {
            if (i2 <= 100) {
                return 7;
            }
            return 7 + ((i2 - 99) / 2);
        }
    }

    protected void checkPoint(ECPoint eCPoint) {
        if (eCPoint == null || this != eCPoint.getCurve()) {
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
            if (eCPoint != null && this != eCPoint.getCurve()) {
                throw new IllegalArgumentException("'points' entries must be null or on this curve");
            }
        }
    }

    protected abstract ECCurve cloneCurve();

    public synchronized Config configure() {
        return new Config(this.coord, this.endomorphism, this.multiplier);
    }

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] eCPointArr, int i, final int i2) {
        final int fieldElementEncodingLength = getFieldElementEncodingLength();
        final byte[] bArr = new byte[i2 * fieldElementEncodingLength * 2];
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            ECPoint eCPoint = eCPointArr[i + i4];
            eCPoint.getRawXCoord().encodeTo(bArr, i3);
            int i5 = i3 + fieldElementEncodingLength;
            eCPoint.getRawYCoord().encodeTo(bArr, i5);
            i3 = i5 + fieldElementEncodingLength;
        }
        return new AbstractECLookupTable() { // from class: org.bouncycastle.math.ec.ECCurve.1
            private ECPoint createPoint(byte[] bArr2, byte[] bArr3) {
                ECCurve eCCurve = ECCurve.this;
                return eCCurve.createRawPoint(eCCurve.fromBigInteger(new BigInteger(1, bArr2)), ECCurve.this.fromBigInteger(new BigInteger(1, bArr3)));
            }

            @Override // org.bouncycastle.math.p016ec.ECLookupTable
            public int getSize() {
                return i2;
            }

            @Override // org.bouncycastle.math.p016ec.ECLookupTable
            public ECPoint lookup(int i6) {
                int i7;
                int i8 = fieldElementEncodingLength;
                byte[] bArr2 = new byte[i8];
                byte[] bArr3 = new byte[i8];
                int i9 = 0;
                for (int i10 = 0; i10 < i2; i10++) {
                    int i11 = ((i10 ^ i6) - 1) >> 31;
                    int i12 = 0;
                    while (true) {
                        i7 = fieldElementEncodingLength;
                        if (i12 < i7) {
                            byte b = bArr2[i12];
                            byte[] bArr4 = bArr;
                            bArr2[i12] = (byte) (b ^ (bArr4[i9 + i12] & i11));
                            bArr3[i12] = (byte) ((bArr4[(i7 + i9) + i12] & i11) ^ bArr3[i12]);
                            i12++;
                        }
                    }
                    i9 += i7 * 2;
                }
                return createPoint(bArr2, bArr3);
            }

            @Override // org.bouncycastle.math.p016ec.AbstractECLookupTable, org.bouncycastle.math.p016ec.ECLookupTable
            public ECPoint lookupVar(int i6) {
                int i7 = fieldElementEncodingLength;
                byte[] bArr2 = new byte[i7];
                byte[] bArr3 = new byte[i7];
                int i8 = i6 * i7 * 2;
                int i9 = 0;
                while (true) {
                    int i10 = fieldElementEncodingLength;
                    if (i9 >= i10) {
                        return createPoint(bArr2, bArr3);
                    }
                    byte[] bArr4 = bArr;
                    bArr2[i9] = bArr4[i8 + i9];
                    bArr3[i9] = bArr4[i10 + i8 + i9];
                    i9++;
                }
            }
        };
    }

    protected ECMultiplier createDefaultMultiplier() {
        return this.endomorphism instanceof GLVEndomorphism ? new GLVMultiplier(this, (GLVEndomorphism) this.endomorphism) : new WNafL2RMultiplier();
    }

    public ECPoint createPoint(BigInteger bigInteger, BigInteger bigInteger2) {
        return createRawPoint(fromBigInteger(bigInteger), fromBigInteger(bigInteger2));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public abstract ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2);

    /* JADX INFO: Access modifiers changed from: protected */
    public abstract ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr);

    public ECPoint decodePoint(byte[] bArr) {
        ECPoint infinity;
        int fieldElementEncodingLength = getFieldElementEncodingLength();
        byte b = bArr[0];
        if (b != 0) {
            if (b == 2 || b == 3) {
                if (bArr.length != fieldElementEncodingLength + 1) {
                    throw new IllegalArgumentException("Incorrect length for compressed encoding");
                }
                infinity = decompressPoint(b & 1, BigIntegers.fromUnsignedByteArray(bArr, 1, fieldElementEncodingLength));
                if (!infinity.implIsValid(true, true)) {
                    throw new IllegalArgumentException("Invalid point");
                }
            } else if (b != 4) {
                if (b != 6 && b != 7) {
                    throw new IllegalArgumentException("Invalid point encoding 0x" + Integer.toString(b, 16));
                }
                if (bArr.length != (fieldElementEncodingLength * 2) + 1) {
                    throw new IllegalArgumentException("Incorrect length for hybrid encoding");
                }
                BigInteger fromUnsignedByteArray = BigIntegers.fromUnsignedByteArray(bArr, 1, fieldElementEncodingLength);
                BigInteger fromUnsignedByteArray2 = BigIntegers.fromUnsignedByteArray(bArr, fieldElementEncodingLength + 1, fieldElementEncodingLength);
                if (fromUnsignedByteArray2.testBit(0) != (b == 7)) {
                    throw new IllegalArgumentException("Inconsistent Y coordinate in hybrid encoding");
                }
                infinity = validatePoint(fromUnsignedByteArray, fromUnsignedByteArray2);
            } else if (bArr.length != (fieldElementEncodingLength * 2) + 1) {
                throw new IllegalArgumentException("Incorrect length for uncompressed encoding");
            } else {
                infinity = validatePoint(BigIntegers.fromUnsignedByteArray(bArr, 1, fieldElementEncodingLength), BigIntegers.fromUnsignedByteArray(bArr, fieldElementEncodingLength + 1, fieldElementEncodingLength));
            }
        } else if (bArr.length != 1) {
            throw new IllegalArgumentException("Incorrect length for infinity encoding");
        } else {
            infinity = getInfinity();
        }
        if (b == 0 || !infinity.isInfinity()) {
            return infinity;
        }
        throw new IllegalArgumentException("Invalid infinity encoding");
    }

    protected abstract ECPoint decompressPoint(int i, BigInteger bigInteger);

    public boolean equals(Object obj) {
        return this == obj || ((obj instanceof ECCurve) && equals((ECCurve) obj));
    }

    public boolean equals(ECCurve eCCurve) {
        return this == eCCurve || (eCCurve != null && getField().equals(eCCurve.getField()) && getA().toBigInteger().equals(eCCurve.getA().toBigInteger()) && getB().toBigInteger().equals(eCCurve.getB().toBigInteger()));
    }

    public abstract ECFieldElement fromBigInteger(BigInteger bigInteger);

    public ECFieldElement getA() {
        return this.f1000a;
    }

    public int getAffinePointEncodingLength(boolean z) {
        int fieldElementEncodingLength = getFieldElementEncodingLength();
        if (!z) {
            fieldElementEncodingLength *= 2;
        }
        return fieldElementEncodingLength + 1;
    }

    public ECFieldElement getB() {
        return this.f1001b;
    }

    public BigInteger getCofactor() {
        return this.cofactor;
    }

    public int getCoordinateSystem() {
        return this.coord;
    }

    public ECEndomorphism getEndomorphism() {
        return this.endomorphism;
    }

    public FiniteField getField() {
        return this.field;
    }

    public int getFieldElementEncodingLength() {
        return (getFieldSize() + 7) / 8;
    }

    public abstract int getFieldSize();

    public abstract ECPoint getInfinity();

    public ECMultiplier getMultiplier() {
        if (this.multiplier == null) {
            this.multiplier = createDefaultMultiplier();
        }
        return this.multiplier;
    }

    public BigInteger getOrder() {
        return this.order;
    }

    public PreCompInfo getPreCompInfo(ECPoint eCPoint, String str) {
        Hashtable hashtable;
        PreCompInfo preCompInfo;
        checkPoint(eCPoint);
        synchronized (eCPoint) {
            hashtable = eCPoint.preCompTable;
        }
        if (hashtable == null) {
            return null;
        }
        synchronized (hashtable) {
            preCompInfo = (PreCompInfo) hashtable.get(str);
        }
        return preCompInfo;
    }

    public int hashCode() {
        return (getField().hashCode() ^ Integers.rotateLeft(getA().toBigInteger().hashCode(), 8)) ^ Integers.rotateLeft(getB().toBigInteger().hashCode(), 16);
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

    public abstract boolean isValidFieldElement(BigInteger bigInteger);

    public void normalizeAll(ECPoint[] eCPointArr) {
        normalizeAll(eCPointArr, 0, eCPointArr.length, null);
    }

    public void normalizeAll(ECPoint[] eCPointArr, int i, int i2, ECFieldElement eCFieldElement) {
        checkPoints(eCPointArr, i, i2);
        int coordinateSystem = getCoordinateSystem();
        if (coordinateSystem == 0 || coordinateSystem == 5) {
            if (eCFieldElement != null) {
                throw new IllegalArgumentException("'iso' not valid for affine coordinates");
            }
            return;
        }
        ECFieldElement[] eCFieldElementArr = new ECFieldElement[i2];
        int[] iArr = new int[i2];
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            int i5 = i + i4;
            ECPoint eCPoint = eCPointArr[i5];
            if (eCPoint != null && (eCFieldElement != null || !eCPoint.isNormalized())) {
                eCFieldElementArr[i3] = eCPoint.getZCoord(0);
                iArr[i3] = i5;
                i3++;
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
    }

    public PreCompInfo precompute(ECPoint eCPoint, String str, PreCompCallback preCompCallback) {
        Hashtable hashtable;
        PreCompInfo precompute;
        checkPoint(eCPoint);
        synchronized (eCPoint) {
            hashtable = eCPoint.preCompTable;
            if (hashtable == null) {
                hashtable = new Hashtable(4);
                eCPoint.preCompTable = hashtable;
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

    public abstract ECFieldElement randomFieldElement(SecureRandom secureRandom);

    public abstract ECFieldElement randomFieldElementMult(SecureRandom secureRandom);

    public boolean supportsCoordinateSystem(int i) {
        return i == 0;
    }

    public ECPoint validatePoint(BigInteger bigInteger, BigInteger bigInteger2) {
        ECPoint createPoint = createPoint(bigInteger, bigInteger2);
        if (createPoint.isValid()) {
            return createPoint;
        }
        throw new IllegalArgumentException("Invalid point coordinates");
    }
}