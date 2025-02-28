package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DSAExt;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.p010ec.ECAlgorithms;
import org.bouncycastle.math.p010ec.ECConstants;
import org.bouncycastle.math.p010ec.ECMultiplier;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.p010ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/signers/ECGOST3410Signer.class */
public class ECGOST3410Signer implements DSAExt {
    ECKeyParameters key;
    SecureRandom random;

    @Override // org.bouncycastle.crypto.DSA
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!z) {
            this.key = (ECPublicKeyParameters) cipherParameters;
        } else if (!(cipherParameters instanceof ParametersWithRandom)) {
            this.random = CryptoServicesRegistrar.getSecureRandom();
            this.key = (ECPrivateKeyParameters) cipherParameters;
        } else {
            ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
            this.random = parametersWithRandom.getRandom();
            this.key = (ECPrivateKeyParameters) parametersWithRandom.getParameters();
        }
    }

    @Override // org.bouncycastle.crypto.DSAExt
    public BigInteger getOrder() {
        return this.key.getParameters().getN();
    }

    @Override // org.bouncycastle.crypto.DSA
    public BigInteger[] generateSignature(byte[] bArr) {
        BigInteger bigInteger = new BigInteger(1, Arrays.reverse(bArr));
        ECDomainParameters parameters = this.key.getParameters();
        BigInteger n = parameters.getN();
        BigInteger d = ((ECPrivateKeyParameters) this.key).getD();
        ECMultiplier createBasePointMultiplier = createBasePointMultiplier();
        while (true) {
            BigInteger createRandomBigInteger = BigIntegers.createRandomBigInteger(n.bitLength(), this.random);
            if (!createRandomBigInteger.equals(ECConstants.ZERO)) {
                BigInteger mod = createBasePointMultiplier.multiply(parameters.getG(), createRandomBigInteger).normalize().getAffineXCoord().toBigInteger().mod(n);
                if (mod.equals(ECConstants.ZERO)) {
                    continue;
                } else {
                    BigInteger mod2 = createRandomBigInteger.multiply(bigInteger).add(d.multiply(mod)).mod(n);
                    if (!mod2.equals(ECConstants.ZERO)) {
                        return new BigInteger[]{mod, mod2};
                    }
                }
            }
        }
    }

    @Override // org.bouncycastle.crypto.DSA
    public boolean verifySignature(byte[] bArr, BigInteger bigInteger, BigInteger bigInteger2) {
        BigInteger bigInteger3 = new BigInteger(1, Arrays.reverse(bArr));
        BigInteger n = this.key.getParameters().getN();
        if (bigInteger.compareTo(ECConstants.ONE) < 0 || bigInteger.compareTo(n) >= 0 || bigInteger2.compareTo(ECConstants.ONE) < 0 || bigInteger2.compareTo(n) >= 0) {
            return false;
        }
        BigInteger modOddInverseVar = BigIntegers.modOddInverseVar(n, bigInteger3);
        ECPoint normalize = ECAlgorithms.sumOfTwoMultiplies(this.key.getParameters().getG(), bigInteger2.multiply(modOddInverseVar).mod(n), ((ECPublicKeyParameters) this.key).getQ(), n.subtract(bigInteger).multiply(modOddInverseVar).mod(n)).normalize();
        if (normalize.isInfinity()) {
            return false;
        }
        return normalize.getAffineXCoord().toBigInteger().mod(n).equals(bigInteger);
    }

    protected ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }
}