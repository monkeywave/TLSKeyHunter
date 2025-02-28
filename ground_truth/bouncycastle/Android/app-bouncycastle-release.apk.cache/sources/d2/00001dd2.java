package org.bouncycastle.crypto.kems;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.BigIntegers;

/* loaded from: classes2.dex */
public class RSAKEMGenerator implements EncapsulatedSecretGenerator {
    private DerivationFunction kdf;
    private final int keyLen;
    private SecureRandom rnd;
    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private static final BigInteger ONE = BigInteger.valueOf(1);

    public RSAKEMGenerator(int i, DerivationFunction derivationFunction, SecureRandom secureRandom) {
        this.keyLen = i;
        this.kdf = derivationFunction;
        this.rnd = secureRandom;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] generateKey(DerivationFunction derivationFunction, BigInteger bigInteger, BigInteger bigInteger2, int i) {
        derivationFunction.init(new KDFParameters(BigIntegers.asUnsignedByteArray((bigInteger.bitLength() + 7) / 8, bigInteger2), null));
        byte[] bArr = new byte[i];
        derivationFunction.generateBytes(bArr, 0, i);
        return bArr;
    }

    @Override // org.bouncycastle.crypto.EncapsulatedSecretGenerator
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter asymmetricKeyParameter) {
        RSAKeyParameters rSAKeyParameters = (RSAKeyParameters) asymmetricKeyParameter;
        if (rSAKeyParameters.isPrivate()) {
            throw new IllegalArgumentException("public key required for encryption");
        }
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("RSAKem", ConstraintUtils.bitsOfSecurityFor(rSAKeyParameters.getModulus()), rSAKeyParameters, CryptoServicePurpose.ENCRYPTION));
        BigInteger modulus = rSAKeyParameters.getModulus();
        BigInteger exponent = rSAKeyParameters.getExponent();
        BigInteger createRandomInRange = BigIntegers.createRandomInRange(ZERO, modulus.subtract(ONE), this.rnd);
        return new SecretWithEncapsulationImpl(generateKey(this.kdf, modulus, createRandomInRange, this.keyLen), BigIntegers.asUnsignedByteArray((modulus.bitLength() + 7) / 8, createRandomInRange.modPow(exponent, modulus)));
    }
}