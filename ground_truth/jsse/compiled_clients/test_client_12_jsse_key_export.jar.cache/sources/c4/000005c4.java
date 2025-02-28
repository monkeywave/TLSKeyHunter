package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DSAExt;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.p010ec.ECAlgorithms;
import org.bouncycastle.math.p010ec.ECConstants;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/signers/ECNRSigner.class */
public class ECNRSigner implements DSAExt {
    private boolean forSigning;
    private ECKeyParameters key;
    private SecureRandom random;

    @Override // org.bouncycastle.crypto.DSA
    public void init(boolean z, CipherParameters cipherParameters) {
        this.forSigning = z;
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
        AsymmetricCipherKeyPair generateKeyPair;
        BigInteger mod;
        if (this.forSigning) {
            BigInteger order = getOrder();
            BigInteger bigInteger = new BigInteger(1, bArr);
            ECPrivateKeyParameters eCPrivateKeyParameters = (ECPrivateKeyParameters) this.key;
            if (bigInteger.compareTo(order) >= 0) {
                throw new DataLengthException("input too large for ECNR key");
            }
            do {
                ECKeyPairGenerator eCKeyPairGenerator = new ECKeyPairGenerator();
                eCKeyPairGenerator.init(new ECKeyGenerationParameters(eCPrivateKeyParameters.getParameters(), this.random));
                generateKeyPair = eCKeyPairGenerator.generateKeyPair();
                mod = ((ECPublicKeyParameters) generateKeyPair.getPublic()).getQ().getAffineXCoord().toBigInteger().add(bigInteger).mod(order);
            } while (mod.equals(ECConstants.ZERO));
            return new BigInteger[]{mod, ((ECPrivateKeyParameters) generateKeyPair.getPrivate()).getD().subtract(mod.multiply(eCPrivateKeyParameters.getD())).mod(order)};
        }
        throw new IllegalStateException("not initialised for signing");
    }

    @Override // org.bouncycastle.crypto.DSA
    public boolean verifySignature(byte[] bArr, BigInteger bigInteger, BigInteger bigInteger2) {
        if (this.forSigning) {
            throw new IllegalStateException("not initialised for verifying");
        }
        ECPublicKeyParameters eCPublicKeyParameters = (ECPublicKeyParameters) this.key;
        BigInteger n = eCPublicKeyParameters.getParameters().getN();
        int bitLength = n.bitLength();
        BigInteger bigInteger3 = new BigInteger(1, bArr);
        if (bigInteger3.bitLength() > bitLength) {
            throw new DataLengthException("input too large for ECNR key.");
        }
        BigInteger extractT = extractT(eCPublicKeyParameters, bigInteger, bigInteger2);
        return extractT != null && extractT.equals(bigInteger3.mod(n));
    }

    public byte[] getRecoveredMessage(BigInteger bigInteger, BigInteger bigInteger2) {
        if (this.forSigning) {
            throw new IllegalStateException("not initialised for verifying/recovery");
        }
        BigInteger extractT = extractT((ECPublicKeyParameters) this.key, bigInteger, bigInteger2);
        if (extractT != null) {
            return BigIntegers.asUnsignedByteArray(extractT);
        }
        return null;
    }

    private BigInteger extractT(ECPublicKeyParameters eCPublicKeyParameters, BigInteger bigInteger, BigInteger bigInteger2) {
        BigInteger n = eCPublicKeyParameters.getParameters().getN();
        if (bigInteger.compareTo(ECConstants.ONE) < 0 || bigInteger.compareTo(n) >= 0 || bigInteger2.compareTo(ECConstants.ZERO) < 0 || bigInteger2.compareTo(n) >= 0) {
            return null;
        }
        ECPoint normalize = ECAlgorithms.sumOfTwoMultiplies(eCPublicKeyParameters.getParameters().getG(), bigInteger2, eCPublicKeyParameters.getQ(), bigInteger).normalize();
        if (normalize.isInfinity()) {
            return null;
        }
        return bigInteger.subtract(normalize.getAffineXCoord().toBigInteger()).mod(n);
    }
}