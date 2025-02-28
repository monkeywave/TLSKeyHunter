package org.bouncycastle.crypto.engines;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.CramerShoupKeyParameters;
import org.bouncycastle.crypto.params.CramerShoupPrivateKeyParameters;
import org.bouncycastle.crypto.params.CramerShoupPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/CramerShoupCoreEngine.class */
public class CramerShoupCoreEngine {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private CramerShoupKeyParameters key;
    private SecureRandom random;
    private boolean forEncryption;
    private byte[] label = null;

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/CramerShoupCoreEngine$CramerShoupCiphertextException.class */
    public static class CramerShoupCiphertextException extends Exception {
        private static final long serialVersionUID = -6360977166495345076L;

        public CramerShoupCiphertextException(String str) {
            super(str);
        }
    }

    public void init(boolean z, CipherParameters cipherParameters, String str) {
        init(z, cipherParameters);
        this.label = Strings.toUTF8ByteArray(str);
    }

    public void init(boolean z, CipherParameters cipherParameters) {
        SecureRandom secureRandom = null;
        if (cipherParameters instanceof ParametersWithRandom) {
            ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
            this.key = (CramerShoupKeyParameters) parametersWithRandom.getParameters();
            secureRandom = parametersWithRandom.getRandom();
        } else {
            this.key = (CramerShoupKeyParameters) cipherParameters;
        }
        this.random = initSecureRandom(z, secureRandom);
        this.forEncryption = z;
    }

    public int getInputBlockSize() {
        int bitLength = this.key.getParameters().getP().bitLength();
        return this.forEncryption ? ((bitLength + 7) / 8) - 1 : (bitLength + 7) / 8;
    }

    public int getOutputBlockSize() {
        int bitLength = this.key.getParameters().getP().bitLength();
        return this.forEncryption ? (bitLength + 7) / 8 : ((bitLength + 7) / 8) - 1;
    }

    public BigInteger convertInput(byte[] bArr, int i, int i2) {
        byte[] bArr2;
        if (i2 > getInputBlockSize() + 1) {
            throw new DataLengthException("input too large for Cramer Shoup cipher.");
        }
        if (i2 == getInputBlockSize() + 1 && this.forEncryption) {
            throw new DataLengthException("input too large for Cramer Shoup cipher.");
        }
        if (i == 0 && i2 == bArr.length) {
            bArr2 = bArr;
        } else {
            bArr2 = new byte[i2];
            System.arraycopy(bArr, i, bArr2, 0, i2);
        }
        BigInteger bigInteger = new BigInteger(1, bArr2);
        if (bigInteger.compareTo(this.key.getParameters().getP()) >= 0) {
            throw new DataLengthException("input too large for Cramer Shoup cipher.");
        }
        return bigInteger;
    }

    public byte[] convertOutput(BigInteger bigInteger) {
        byte[] byteArray = bigInteger.toByteArray();
        if (this.forEncryption) {
            if (byteArray[0] == 0) {
                byte[] bArr = new byte[byteArray.length - 1];
                System.arraycopy(byteArray, 1, bArr, 0, bArr.length);
                return bArr;
            }
        } else if (byteArray[0] == 0 && byteArray.length > getOutputBlockSize()) {
            byte[] bArr2 = new byte[byteArray.length - 1];
            System.arraycopy(byteArray, 1, bArr2, 0, bArr2.length);
            return bArr2;
        } else if (byteArray.length < getOutputBlockSize()) {
            byte[] bArr3 = new byte[getOutputBlockSize()];
            System.arraycopy(byteArray, 0, bArr3, bArr3.length - byteArray.length, byteArray.length);
            return bArr3;
        }
        return byteArray;
    }

    public CramerShoupCiphertext encryptBlock(BigInteger bigInteger) {
        CramerShoupCiphertext cramerShoupCiphertext = null;
        if (!this.key.isPrivate() && this.forEncryption && (this.key instanceof CramerShoupPublicKeyParameters)) {
            CramerShoupPublicKeyParameters cramerShoupPublicKeyParameters = (CramerShoupPublicKeyParameters) this.key;
            BigInteger p = cramerShoupPublicKeyParameters.getParameters().getP();
            BigInteger g1 = cramerShoupPublicKeyParameters.getParameters().getG1();
            BigInteger g2 = cramerShoupPublicKeyParameters.getParameters().getG2();
            BigInteger h = cramerShoupPublicKeyParameters.getH();
            if (!isValidMessage(bigInteger, p)) {
                return null;
            }
            BigInteger generateRandomElement = generateRandomElement(p, this.random);
            BigInteger modPow = g1.modPow(generateRandomElement, p);
            BigInteger modPow2 = g2.modPow(generateRandomElement, p);
            BigInteger mod = h.modPow(generateRandomElement, p).multiply(bigInteger).mod(p);
            Digest h2 = cramerShoupPublicKeyParameters.getParameters().getH();
            byte[] byteArray = modPow.toByteArray();
            h2.update(byteArray, 0, byteArray.length);
            byte[] byteArray2 = modPow2.toByteArray();
            h2.update(byteArray2, 0, byteArray2.length);
            byte[] byteArray3 = mod.toByteArray();
            h2.update(byteArray3, 0, byteArray3.length);
            if (this.label != null) {
                byte[] bArr = this.label;
                h2.update(bArr, 0, bArr.length);
            }
            byte[] bArr2 = new byte[h2.getDigestSize()];
            h2.doFinal(bArr2, 0);
            cramerShoupCiphertext = new CramerShoupCiphertext(modPow, modPow2, mod, cramerShoupPublicKeyParameters.getC().modPow(generateRandomElement, p).multiply(cramerShoupPublicKeyParameters.getD().modPow(generateRandomElement.multiply(new BigInteger(1, bArr2)), p)).mod(p));
        }
        return cramerShoupCiphertext;
    }

    public BigInteger decryptBlock(CramerShoupCiphertext cramerShoupCiphertext) throws CramerShoupCiphertextException {
        BigInteger bigInteger = null;
        if (this.key.isPrivate() && !this.forEncryption && (this.key instanceof CramerShoupPrivateKeyParameters)) {
            CramerShoupPrivateKeyParameters cramerShoupPrivateKeyParameters = (CramerShoupPrivateKeyParameters) this.key;
            BigInteger p = cramerShoupPrivateKeyParameters.getParameters().getP();
            Digest h = cramerShoupPrivateKeyParameters.getParameters().getH();
            byte[] byteArray = cramerShoupCiphertext.getU1().toByteArray();
            h.update(byteArray, 0, byteArray.length);
            byte[] byteArray2 = cramerShoupCiphertext.getU2().toByteArray();
            h.update(byteArray2, 0, byteArray2.length);
            byte[] byteArray3 = cramerShoupCiphertext.getE().toByteArray();
            h.update(byteArray3, 0, byteArray3.length);
            if (this.label != null) {
                byte[] bArr = this.label;
                h.update(bArr, 0, bArr.length);
            }
            byte[] bArr2 = new byte[h.getDigestSize()];
            h.doFinal(bArr2, 0);
            BigInteger bigInteger2 = new BigInteger(1, bArr2);
            if (!cramerShoupCiphertext.f323v.equals(cramerShoupCiphertext.f320u1.modPow(cramerShoupPrivateKeyParameters.getX1().add(cramerShoupPrivateKeyParameters.getY1().multiply(bigInteger2)), p).multiply(cramerShoupCiphertext.f321u2.modPow(cramerShoupPrivateKeyParameters.getX2().add(cramerShoupPrivateKeyParameters.getY2().multiply(bigInteger2)), p)).mod(p))) {
                throw new CramerShoupCiphertextException("Sorry, that ciphertext is not correct");
            }
            bigInteger = cramerShoupCiphertext.f322e.multiply(cramerShoupCiphertext.f320u1.modPow(cramerShoupPrivateKeyParameters.getZ(), p).modInverse(p)).mod(p);
        }
        return bigInteger;
    }

    private BigInteger generateRandomElement(BigInteger bigInteger, SecureRandom secureRandom) {
        return BigIntegers.createRandomInRange(ONE, bigInteger.subtract(ONE), secureRandom);
    }

    private boolean isValidMessage(BigInteger bigInteger, BigInteger bigInteger2) {
        return bigInteger.compareTo(bigInteger2) < 0;
    }

    protected SecureRandom initSecureRandom(boolean z, SecureRandom secureRandom) {
        if (z) {
            return CryptoServicesRegistrar.getSecureRandom(secureRandom);
        }
        return null;
    }
}