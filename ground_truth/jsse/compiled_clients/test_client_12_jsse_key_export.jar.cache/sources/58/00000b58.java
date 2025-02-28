package org.bouncycastle.jcajce.provider.symmetric.util;

import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import javax.security.auth.Destroyable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/symmetric/util/BCPBEKey.class */
public class BCPBEKey implements PBEKey, Destroyable {
    private final AtomicBoolean hasBeenDestroyed;
    String algorithm;
    ASN1ObjectIdentifier oid;
    int type;
    int digest;
    int keySize;
    int ivSize;
    private final char[] password;
    private final byte[] salt;
    private final int iterationCount;
    private final CipherParameters param;
    boolean tryWrong;

    public BCPBEKey(String str, ASN1ObjectIdentifier aSN1ObjectIdentifier, int i, int i2, int i3, int i4, PBEKeySpec pBEKeySpec, CipherParameters cipherParameters) {
        this.hasBeenDestroyed = new AtomicBoolean(false);
        this.tryWrong = false;
        this.algorithm = str;
        this.oid = aSN1ObjectIdentifier;
        this.type = i;
        this.digest = i2;
        this.keySize = i3;
        this.ivSize = i4;
        this.password = pBEKeySpec.getPassword();
        this.iterationCount = pBEKeySpec.getIterationCount();
        this.salt = pBEKeySpec.getSalt();
        this.param = cipherParameters;
    }

    public BCPBEKey(String str, CipherParameters cipherParameters) {
        this.hasBeenDestroyed = new AtomicBoolean(false);
        this.tryWrong = false;
        this.algorithm = str;
        this.param = cipherParameters;
        this.password = null;
        this.iterationCount = -1;
        this.salt = null;
    }

    @Override // java.security.Key
    public String getAlgorithm() {
        checkDestroyed(this);
        return this.algorithm;
    }

    @Override // java.security.Key
    public String getFormat() {
        return "RAW";
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        checkDestroyed(this);
        if (this.param != null) {
            return (this.param instanceof ParametersWithIV ? (KeyParameter) ((ParametersWithIV) this.param).getParameters() : (KeyParameter) this.param).getKey();
        }
        return this.type == 2 ? PBEParametersGenerator.PKCS12PasswordToBytes(this.password) : this.type == 5 ? PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(this.password) : PBEParametersGenerator.PKCS5PasswordToBytes(this.password);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getType() {
        checkDestroyed(this);
        return this.type;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getDigest() {
        checkDestroyed(this);
        return this.digest;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getKeySize() {
        checkDestroyed(this);
        return this.keySize;
    }

    public int getIvSize() {
        checkDestroyed(this);
        return this.ivSize;
    }

    public CipherParameters getParam() {
        checkDestroyed(this);
        return this.param;
    }

    @Override // javax.crypto.interfaces.PBEKey
    public char[] getPassword() {
        checkDestroyed(this);
        if (this.password == null) {
            throw new IllegalStateException("no password available");
        }
        return Arrays.clone(this.password);
    }

    @Override // javax.crypto.interfaces.PBEKey
    public byte[] getSalt() {
        checkDestroyed(this);
        return Arrays.clone(this.salt);
    }

    @Override // javax.crypto.interfaces.PBEKey
    public int getIterationCount() {
        checkDestroyed(this);
        return this.iterationCount;
    }

    public ASN1ObjectIdentifier getOID() {
        checkDestroyed(this);
        return this.oid;
    }

    public void setTryWrongPKCS12Zero(boolean z) {
        this.tryWrong = z;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean shouldTryWrongPKCS12() {
        return this.tryWrong;
    }

    @Override // javax.security.auth.Destroyable
    public void destroy() {
        if (this.hasBeenDestroyed.getAndSet(true)) {
            return;
        }
        if (this.password != null) {
            Arrays.fill(this.password, (char) 0);
        }
        if (this.salt != null) {
            Arrays.fill(this.salt, (byte) 0);
        }
    }

    @Override // javax.security.auth.Destroyable
    public boolean isDestroyed() {
        return this.hasBeenDestroyed.get();
    }

    static void checkDestroyed(Destroyable destroyable) {
        if (destroyable.isDestroyed()) {
            throw new IllegalStateException("key has been destroyed");
        }
    }
}