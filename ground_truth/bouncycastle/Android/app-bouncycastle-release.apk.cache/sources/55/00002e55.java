package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.AccessController;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class JceAEADCipherImpl implements TlsAEADCipherImpl {
    private static final boolean canDoAEAD = checkForAEAD();
    private final String algorithm;
    private final String algorithmParamsName;
    private final Cipher cipher;
    private final int cipherMode;
    private final JcaTlsCrypto crypto;
    private final JcaJceHelper helper;
    private SecretKey key;
    private final int keySize;
    private int macSize;
    private byte[] nonce;

    public JceAEADCipherImpl(JcaTlsCrypto jcaTlsCrypto, JcaJceHelper jcaJceHelper, String str, String str2, int i, boolean z) throws GeneralSecurityException {
        this.crypto = jcaTlsCrypto;
        this.helper = jcaJceHelper;
        this.cipher = jcaJceHelper.createCipher(str);
        this.algorithm = str2;
        this.keySize = i;
        this.cipherMode = z ? 1 : 2;
        this.algorithmParamsName = getAlgParamsName(jcaJceHelper, str);
    }

    private static boolean checkForAEAD() {
        return ((Boolean) AccessController.doPrivileged(new PrivilegedAction() { // from class: org.bouncycastle.tls.crypto.impl.jcajce.JceAEADCipherImpl.1
            @Override // java.security.PrivilegedAction
            public Object run() {
                try {
                    boolean z = true;
                    if (Cipher.class.getMethod("updateAAD", byte[].class) == null) {
                        z = false;
                    }
                    return Boolean.valueOf(z);
                } catch (Exception unused) {
                    return Boolean.FALSE;
                }
            }
        })).booleanValue();
    }

    private static String getAlgParamsName(JcaJceHelper jcaJceHelper, String str) {
        String str2 = "CCM";
        try {
            if (!str.contains("CCM")) {
                str2 = "GCM";
            }
            jcaJceHelper.createAlgorithmParameters(str2);
            return str2;
        } catch (Exception unused) {
            return null;
        }
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public int doFinal(byte[] bArr, byte[] bArr2, int i, int i2, byte[] bArr3, int i3) throws IOException {
        if (!Arrays.isNullOrEmpty(bArr)) {
            if (canDoAEAD) {
                this.cipher.updateAAD(bArr);
            } else {
                try {
                    this.cipher.init(this.cipherMode, this.key, new AEADParameterSpec(this.nonce, this.macSize * 8, bArr));
                } catch (Exception e) {
                    throw new IOException(e);
                }
            }
        }
        try {
            return this.cipher.doFinal(bArr2, i, i2, bArr3, i3);
        } catch (GeneralSecurityException e2) {
            throw Exceptions.illegalStateException("", e2);
        }
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public int getOutputSize(int i) {
        return this.cipher.getOutputSize(i);
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public void init(byte[] bArr, int i) {
        String str;
        SecureRandom secureRandom = this.crypto.getSecureRandom();
        try {
            if (!canDoAEAD || (str = this.algorithmParamsName) == null) {
                this.cipher.init(this.cipherMode, this.key, new AEADParameterSpec(bArr, i * 8, null), secureRandom);
                this.nonce = Arrays.clone(bArr);
                this.macSize = i;
                return;
            }
            AlgorithmParameters createAlgorithmParameters = this.helper.createAlgorithmParameters(str);
            if (GCMUtil.isGCMParameterSpecAvailable()) {
                createAlgorithmParameters.init(GCMUtil.createGCMParameterSpec(i * 8, bArr));
            } else {
                createAlgorithmParameters.init(new GCMParameters(bArr, i).getEncoded());
            }
            this.cipher.init(this.cipherMode, this.key, createAlgorithmParameters, secureRandom);
        } catch (Exception e) {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public void setKey(byte[] bArr, int i, int i2) {
        if (this.keySize != i2) {
            throw new IllegalStateException();
        }
        this.key = new SecretKeySpec(bArr, i, i2, this.algorithm);
    }
}