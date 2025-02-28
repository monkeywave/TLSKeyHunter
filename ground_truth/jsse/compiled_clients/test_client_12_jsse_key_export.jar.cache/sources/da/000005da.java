package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.p010ec.ECAlgorithms;
import org.bouncycastle.math.p010ec.ECConstants;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.p010ec.ECMultiplier;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.p010ec.FixedPointCombMultiplier;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/signers/SM2Signer.class */
public class SM2Signer implements Signer, ECConstants {
    private final DSAKCalculator kCalculator;
    private final Digest digest;
    private final DSAEncoding encoding;
    private ECDomainParameters ecParams;
    private ECPoint pubPoint;
    private ECKeyParameters ecKey;

    /* renamed from: z */
    private byte[] f587z;

    public SM2Signer() {
        this(StandardDSAEncoding.INSTANCE, new SM3Digest());
    }

    public SM2Signer(Digest digest) {
        this(StandardDSAEncoding.INSTANCE, digest);
    }

    public SM2Signer(DSAEncoding dSAEncoding) {
        this.kCalculator = new RandomDSAKCalculator();
        this.encoding = dSAEncoding;
        this.digest = new SM3Digest();
    }

    public SM2Signer(DSAEncoding dSAEncoding, Digest digest) {
        this.kCalculator = new RandomDSAKCalculator();
        this.encoding = dSAEncoding;
        this.digest = digest;
    }

    @Override // org.bouncycastle.crypto.Signer
    public void init(boolean z, CipherParameters cipherParameters) {
        CipherParameters cipherParameters2;
        byte[] decodeStrict;
        if (cipherParameters instanceof ParametersWithID) {
            cipherParameters2 = ((ParametersWithID) cipherParameters).getParameters();
            decodeStrict = ((ParametersWithID) cipherParameters).getID();
            if (decodeStrict.length >= 8192) {
                throw new IllegalArgumentException("SM2 user ID must be less than 2^16 bits long");
            }
        } else {
            cipherParameters2 = cipherParameters;
            decodeStrict = Hex.decodeStrict("31323334353637383132333435363738");
        }
        if (z) {
            if (cipherParameters2 instanceof ParametersWithRandom) {
                ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters2;
                this.ecKey = (ECKeyParameters) parametersWithRandom.getParameters();
                this.ecParams = this.ecKey.getParameters();
                this.kCalculator.init(this.ecParams.getN(), parametersWithRandom.getRandom());
            } else {
                this.ecKey = (ECKeyParameters) cipherParameters2;
                this.ecParams = this.ecKey.getParameters();
                this.kCalculator.init(this.ecParams.getN(), CryptoServicesRegistrar.getSecureRandom());
            }
            this.pubPoint = createBasePointMultiplier().multiply(this.ecParams.getG(), ((ECPrivateKeyParameters) this.ecKey).getD()).normalize();
        } else {
            this.ecKey = (ECKeyParameters) cipherParameters2;
            this.ecParams = this.ecKey.getParameters();
            this.pubPoint = ((ECPublicKeyParameters) this.ecKey).getQ();
        }
        this.f587z = getZ(decodeStrict);
        this.digest.update(this.f587z, 0, this.f587z.length);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void update(byte b) {
        this.digest.update(b);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void update(byte[] bArr, int i, int i2) {
        this.digest.update(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.Signer
    public boolean verifySignature(byte[] bArr) {
        try {
            BigInteger[] decode = this.encoding.decode(this.ecParams.getN(), bArr);
            return verifySignature(decode[0], decode[1]);
        } catch (Exception e) {
            return false;
        }
    }

    @Override // org.bouncycastle.crypto.Signer
    public void reset() {
        this.digest.reset();
        if (this.f587z != null) {
            this.digest.update(this.f587z, 0, this.f587z.length);
        }
    }

    @Override // org.bouncycastle.crypto.Signer
    public byte[] generateSignature() throws CryptoException {
        byte[] digestDoFinal = digestDoFinal();
        BigInteger n = this.ecParams.getN();
        BigInteger calculateE = calculateE(n, digestDoFinal);
        BigInteger d = ((ECPrivateKeyParameters) this.ecKey).getD();
        ECMultiplier createBasePointMultiplier = createBasePointMultiplier();
        while (true) {
            BigInteger nextK = this.kCalculator.nextK();
            BigInteger mod = calculateE.add(createBasePointMultiplier.multiply(this.ecParams.getG(), nextK).normalize().getAffineXCoord().toBigInteger()).mod(n);
            if (!mod.equals(ZERO) && !mod.add(nextK).equals(n)) {
                BigInteger mod2 = BigIntegers.modOddInverse(n, d.add(ONE)).multiply(nextK.subtract(mod.multiply(d)).mod(n)).mod(n);
                if (!mod2.equals(ZERO)) {
                    try {
                        return this.encoding.encode(this.ecParams.getN(), mod, mod2);
                    } catch (Exception e) {
                        throw new CryptoException("unable to encode signature: " + e.getMessage(), e);
                    }
                }
            }
        }
    }

    private boolean verifySignature(BigInteger bigInteger, BigInteger bigInteger2) {
        BigInteger n = this.ecParams.getN();
        if (bigInteger.compareTo(ONE) < 0 || bigInteger.compareTo(n) >= 0 || bigInteger2.compareTo(ONE) < 0 || bigInteger2.compareTo(n) >= 0) {
            return false;
        }
        BigInteger calculateE = calculateE(n, digestDoFinal());
        BigInteger mod = bigInteger.add(bigInteger2).mod(n);
        if (mod.equals(ZERO)) {
            return false;
        }
        ECPoint normalize = ECAlgorithms.sumOfTwoMultiplies(this.ecParams.getG(), bigInteger2, ((ECPublicKeyParameters) this.ecKey).getQ(), mod).normalize();
        if (normalize.isInfinity()) {
            return false;
        }
        return calculateE.add(normalize.getAffineXCoord().toBigInteger()).mod(n).equals(bigInteger);
    }

    private byte[] digestDoFinal() {
        byte[] bArr = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(bArr, 0);
        reset();
        return bArr;
    }

    private byte[] getZ(byte[] bArr) {
        this.digest.reset();
        addUserID(this.digest, bArr);
        addFieldElement(this.digest, this.ecParams.getCurve().getA());
        addFieldElement(this.digest, this.ecParams.getCurve().getB());
        addFieldElement(this.digest, this.ecParams.getG().getAffineXCoord());
        addFieldElement(this.digest, this.ecParams.getG().getAffineYCoord());
        addFieldElement(this.digest, this.pubPoint.getAffineXCoord());
        addFieldElement(this.digest, this.pubPoint.getAffineYCoord());
        byte[] bArr2 = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(bArr2, 0);
        return bArr2;
    }

    private void addUserID(Digest digest, byte[] bArr) {
        int length = bArr.length * 8;
        digest.update((byte) ((length >> 8) & GF2Field.MASK));
        digest.update((byte) (length & GF2Field.MASK));
        digest.update(bArr, 0, bArr.length);
    }

    private void addFieldElement(Digest digest, ECFieldElement eCFieldElement) {
        byte[] encoded = eCFieldElement.getEncoded();
        digest.update(encoded, 0, encoded.length);
    }

    protected ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }

    protected BigInteger calculateE(BigInteger bigInteger, byte[] bArr) {
        return new BigInteger(1, bArr);
    }
}