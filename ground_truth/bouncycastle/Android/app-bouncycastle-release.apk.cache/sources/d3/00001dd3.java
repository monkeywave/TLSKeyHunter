package org.bouncycastle.crypto.kems;

import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.KeyEncapsulation;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class RSAKeyEncapsulation implements KeyEncapsulation {
    private DerivationFunction kdf;
    private RSAKeyParameters key;
    private SecureRandom rnd;

    public RSAKeyEncapsulation(DerivationFunction derivationFunction, SecureRandom secureRandom) {
        this.kdf = derivationFunction;
        this.rnd = secureRandom;
    }

    public CipherParameters decrypt(byte[] bArr, int i) {
        return decrypt(bArr, 0, bArr.length, i);
    }

    @Override // org.bouncycastle.crypto.KeyEncapsulation
    public CipherParameters decrypt(byte[] bArr, int i, int i2, int i3) throws IllegalArgumentException {
        if (this.key.isPrivate()) {
            return new KeyParameter(new RSAKEMExtractor(this.key, i3, this.kdf).extractSecret(Arrays.copyOfRange(bArr, i, i2 + i)));
        }
        throw new IllegalArgumentException("Private key required for decryption");
    }

    public CipherParameters encrypt(byte[] bArr, int i) {
        return encrypt(bArr, 0, i);
    }

    @Override // org.bouncycastle.crypto.KeyEncapsulation
    public CipherParameters encrypt(byte[] bArr, int i, int i2) throws IllegalArgumentException {
        if (this.key.isPrivate()) {
            throw new IllegalArgumentException("Public key required for encryption");
        }
        SecretWithEncapsulation generateEncapsulated = new RSAKEMGenerator(i2, this.kdf, this.rnd).generateEncapsulated(this.key);
        byte[] encapsulation = generateEncapsulated.getEncapsulation();
        System.arraycopy(encapsulation, 0, bArr, i, encapsulation.length);
        return new KeyParameter(generateEncapsulated.getSecret());
    }

    @Override // org.bouncycastle.crypto.KeyEncapsulation
    public void init(CipherParameters cipherParameters) throws IllegalArgumentException {
        if (!(cipherParameters instanceof RSAKeyParameters)) {
            throw new IllegalArgumentException("RSA key required");
        }
        this.key = (RSAKeyParameters) cipherParameters;
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("RSAKem", ConstraintUtils.bitsOfSecurityFor(this.key.getModulus()), cipherParameters, this.key.isPrivate() ? CryptoServicePurpose.DECRYPTION : CryptoServicePurpose.ENCRYPTION));
    }
}