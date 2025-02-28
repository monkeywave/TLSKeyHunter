package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.DHGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.util.BigIntegers;

/* loaded from: classes2.dex */
public class JceTlsDHDomain implements TlsDHDomain {
    protected final JcaTlsCrypto crypto;
    protected final TlsDHConfig dhConfig;
    protected final DHParameterSpec dhSpec;

    public JceTlsDHDomain(JcaTlsCrypto jcaTlsCrypto, TlsDHConfig tlsDHConfig) {
        DHParameterSpec dHParameterSpec;
        DHGroup dHGroup = TlsDHUtils.getDHGroup(tlsDHConfig);
        if (dHGroup == null || (dHParameterSpec = DHUtil.getDHParameterSpec(jcaTlsCrypto, dHGroup)) == null) {
            throw new IllegalArgumentException("No DH configuration provided");
        }
        this.crypto = jcaTlsCrypto;
        this.dhConfig = tlsDHConfig;
        this.dhSpec = dHParameterSpec;
    }

    public static JceTlsSecret calculateDHAgreement(JcaTlsCrypto jcaTlsCrypto, DHPrivateKey dHPrivateKey, DHPublicKey dHPublicKey, boolean z) throws IOException {
        try {
            byte[] calculateKeyAgreement = jcaTlsCrypto.calculateKeyAgreement("DiffieHellman", dHPrivateKey, dHPublicKey, "TlsPremasterSecret");
            if (z) {
                int valueLength = getValueLength(dHPrivateKey.getParams());
                byte[] bArr = new byte[valueLength];
                System.arraycopy(calculateKeyAgreement, 0, bArr, valueLength - calculateKeyAgreement.length, calculateKeyAgreement.length);
                Arrays.fill(calculateKeyAgreement, (byte) 0);
                calculateKeyAgreement = bArr;
            }
            return jcaTlsCrypto.adoptLocalSecret(calculateKeyAgreement);
        } catch (GeneralSecurityException e) {
            throw new TlsCryptoException("cannot calculate secret", e);
        }
    }

    private static byte[] encodeValue(DHParameterSpec dHParameterSpec, boolean z, BigInteger bigInteger) {
        return z ? BigIntegers.asUnsignedByteArray(getValueLength(dHParameterSpec), bigInteger) : BigIntegers.asUnsignedByteArray(bigInteger);
    }

    private static int getValueLength(DHParameterSpec dHParameterSpec) {
        return (dHParameterSpec.getP().bitLength() + 7) / 8;
    }

    public JceTlsSecret calculateDHAgreement(DHPrivateKey dHPrivateKey, DHPublicKey dHPublicKey) throws IOException {
        return calculateDHAgreement(this.crypto, dHPrivateKey, dHPublicKey, this.dhConfig.isPadded());
    }

    @Override // org.bouncycastle.tls.crypto.TlsDHDomain
    public TlsAgreement createDH() {
        return new JceTlsDH(this);
    }

    public BigInteger decodeParameter(byte[] bArr) throws IOException {
        if (!this.dhConfig.isPadded() || getValueLength(this.dhSpec) == bArr.length) {
            return new BigInteger(1, bArr);
        }
        throw new TlsFatalAlert((short) 47);
    }

    public DHPublicKey decodePublicKey(byte[] bArr) throws IOException {
        try {
            return (DHPublicKey) this.crypto.getHelper().createKeyFactory("DiffieHellman").generatePublic(DHUtil.createPublicKeySpec(decodeParameter(bArr), this.dhSpec));
        } catch (IOException e) {
            throw e;
        } catch (Exception e2) {
            throw new TlsFatalAlert((short) 40, (Throwable) e2);
        }
    }

    public byte[] encodeParameter(BigInteger bigInteger) throws IOException {
        return encodeValue(this.dhSpec, this.dhConfig.isPadded(), bigInteger);
    }

    public byte[] encodePublicKey(DHPublicKey dHPublicKey) throws IOException {
        return encodeValue(this.dhSpec, true, dHPublicKey.getY());
    }

    public KeyPair generateKeyPair() throws IOException {
        try {
            KeyPairGenerator createKeyPairGenerator = this.crypto.getHelper().createKeyPairGenerator("DiffieHellman");
            createKeyPairGenerator.initialize(this.dhSpec, this.crypto.getSecureRandom());
            return createKeyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new TlsCryptoException("unable to create key pair", e);
        }
    }
}