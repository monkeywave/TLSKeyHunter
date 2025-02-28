package org.bouncycastle.jcajce.provider.symmetric.util;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.crypto.params.ParametersWithUKM;
import org.bouncycastle.jcajce.provider.symmetric.util.PBE;
import org.bouncycastle.jcajce.spec.GOST28147WrapParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/symmetric/util/BaseWrapCipher.class */
public abstract class BaseWrapCipher extends CipherSpi implements PBE {
    private Class[] availableSpecs;
    protected int pbeType;
    protected int pbeHash;
    protected int pbeKeySize;
    protected int pbeIvSize;
    protected AlgorithmParameters engineParams;
    protected Wrapper wrapEngine;
    private int ivSize;

    /* renamed from: iv */
    private byte[] f619iv;
    private ErasableOutputStream wrapStream;
    private boolean forWrapping;
    private final JcaJceHelper helper;

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/symmetric/util/BaseWrapCipher$ErasableOutputStream.class */
    public static final class ErasableOutputStream extends ByteArrayOutputStream {
        public byte[] getBuf() {
            return this.buf;
        }

        public void erase() {
            Arrays.fill(this.buf, (byte) 0);
            reset();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/symmetric/util/BaseWrapCipher$InvalidKeyOrParametersException.class */
    public static class InvalidKeyOrParametersException extends InvalidKeyException {
        private final Throwable cause;

        /* JADX INFO: Access modifiers changed from: package-private */
        public InvalidKeyOrParametersException(String str, Throwable th) {
            super(str);
            this.cause = th;
        }

        @Override // java.lang.Throwable
        public Throwable getCause() {
            return this.cause;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public BaseWrapCipher() {
        this.availableSpecs = new Class[]{GOST28147WrapParameterSpec.class, PBEParameterSpec.class, RC2ParameterSpec.class, RC5ParameterSpec.class, IvParameterSpec.class};
        this.pbeType = 2;
        this.pbeHash = 1;
        this.engineParams = null;
        this.wrapEngine = null;
        this.wrapStream = null;
        this.helper = new BCJcaJceHelper();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public BaseWrapCipher(Wrapper wrapper) {
        this(wrapper, 0);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public BaseWrapCipher(Wrapper wrapper, int i) {
        this.availableSpecs = new Class[]{GOST28147WrapParameterSpec.class, PBEParameterSpec.class, RC2ParameterSpec.class, RC5ParameterSpec.class, IvParameterSpec.class};
        this.pbeType = 2;
        this.pbeHash = 1;
        this.engineParams = null;
        this.wrapEngine = null;
        this.wrapStream = null;
        this.helper = new BCJcaJceHelper();
        this.wrapEngine = wrapper;
        this.ivSize = i;
    }

    @Override // javax.crypto.CipherSpi
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override // javax.crypto.CipherSpi
    protected byte[] engineGetIV() {
        return Arrays.clone(this.f619iv);
    }

    @Override // javax.crypto.CipherSpi
    protected int engineGetKeySize(Key key) {
        return key.getEncoded().length * 8;
    }

    @Override // javax.crypto.CipherSpi
    protected int engineGetOutputSize(int i) {
        return -1;
    }

    @Override // javax.crypto.CipherSpi
    protected AlgorithmParameters engineGetParameters() {
        if (this.engineParams == null && this.f619iv != null) {
            String algorithmName = this.wrapEngine.getAlgorithmName();
            if (algorithmName.indexOf(47) >= 0) {
                algorithmName = algorithmName.substring(0, algorithmName.indexOf(47));
            }
            try {
                this.engineParams = createParametersInstance(algorithmName);
                this.engineParams.init(new IvParameterSpec(this.f619iv));
            } catch (Exception e) {
                throw new RuntimeException(e.toString());
            }
        }
        return this.engineParams;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final AlgorithmParameters createParametersInstance(String str) throws NoSuchAlgorithmException, NoSuchProviderException {
        return this.helper.createAlgorithmParameters(str);
    }

    @Override // javax.crypto.CipherSpi
    protected void engineSetMode(String str) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("can't support mode " + str);
    }

    @Override // javax.crypto.CipherSpi
    protected void engineSetPadding(String str) throws NoSuchPaddingException {
        throw new NoSuchPaddingException("Padding " + str + " unknown.");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v29, types: [org.bouncycastle.crypto.params.ParametersWithRandom] */
    /* JADX WARN: Type inference failed for: r0v35, types: [org.bouncycastle.crypto.params.ParametersWithIV] */
    /* JADX WARN: Type inference failed for: r0v42, types: [org.bouncycastle.crypto.params.ParametersWithUKM] */
    /* JADX WARN: Type inference failed for: r0v43, types: [org.bouncycastle.crypto.params.ParametersWithSBox] */
    /* JADX WARN: Type inference failed for: r0v47, types: [org.bouncycastle.crypto.params.ParametersWithIV] */
    /* JADX WARN: Type inference failed for: r0v58, types: [org.bouncycastle.crypto.CipherParameters] */
    @Override // javax.crypto.CipherSpi
    protected void engineInit(int i, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        KeyParameter keyParameter;
        if (key instanceof BCPBEKey) {
            BCPBEKey bCPBEKey = (BCPBEKey) key;
            if (algorithmParameterSpec instanceof PBEParameterSpec) {
                keyParameter = PBE.Util.makePBEParameters(bCPBEKey, algorithmParameterSpec, this.wrapEngine.getAlgorithmName());
            } else if (bCPBEKey.getParam() == null) {
                throw new InvalidAlgorithmParameterException("PBE requires PBE parameters to be set.");
            } else {
                keyParameter = bCPBEKey.getParam();
            }
        } else {
            keyParameter = new KeyParameter(key.getEncoded());
        }
        if (algorithmParameterSpec instanceof IvParameterSpec) {
            this.f619iv = ((IvParameterSpec) algorithmParameterSpec).getIV();
            keyParameter = new ParametersWithIV(keyParameter, this.f619iv);
        }
        if (algorithmParameterSpec instanceof GOST28147WrapParameterSpec) {
            GOST28147WrapParameterSpec gOST28147WrapParameterSpec = (GOST28147WrapParameterSpec) algorithmParameterSpec;
            byte[] sBox = gOST28147WrapParameterSpec.getSBox();
            if (sBox != null) {
                keyParameter = new ParametersWithSBox(keyParameter, sBox);
            }
            keyParameter = new ParametersWithUKM(keyParameter, gOST28147WrapParameterSpec.getUKM());
        }
        if ((keyParameter instanceof KeyParameter) && this.ivSize != 0 && (i == 3 || i == 1)) {
            this.f619iv = new byte[this.ivSize];
            secureRandom.nextBytes(this.f619iv);
            keyParameter = new ParametersWithIV(keyParameter, this.f619iv);
        }
        if (secureRandom != null) {
            keyParameter = new ParametersWithRandom(keyParameter, secureRandom);
        }
        try {
            switch (i) {
                case 1:
                    this.wrapEngine.init(true, keyParameter);
                    this.wrapStream = new ErasableOutputStream();
                    this.forWrapping = true;
                    break;
                case 2:
                    this.wrapEngine.init(false, keyParameter);
                    this.wrapStream = new ErasableOutputStream();
                    this.forWrapping = false;
                    break;
                case 3:
                    this.wrapEngine.init(true, keyParameter);
                    this.wrapStream = null;
                    this.forWrapping = true;
                    break;
                case 4:
                    this.wrapEngine.init(false, keyParameter);
                    this.wrapStream = null;
                    this.forWrapping = false;
                    break;
                default:
                    throw new InvalidParameterException("Unknown mode parameter passed to init.");
            }
        } catch (Exception e) {
            throw new InvalidKeyOrParametersException(e.getMessage(), e);
        }
    }

    @Override // javax.crypto.CipherSpi
    protected void engineInit(int i, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec algorithmParameterSpec = null;
        if (algorithmParameters != null) {
            algorithmParameterSpec = SpecUtil.extractSpec(algorithmParameters, this.availableSpecs);
            if (algorithmParameterSpec == null) {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + algorithmParameters.toString());
            }
        }
        this.engineParams = algorithmParameters;
        engineInit(i, key, algorithmParameterSpec, secureRandom);
    }

    @Override // javax.crypto.CipherSpi
    protected void engineInit(int i, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        try {
            engineInit(i, key, (AlgorithmParameterSpec) null, secureRandom);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyOrParametersException(e.getMessage(), e);
        }
    }

    @Override // javax.crypto.CipherSpi
    protected byte[] engineUpdate(byte[] bArr, int i, int i2) {
        if (this.wrapStream == null) {
            throw new IllegalStateException("not supported in a wrapping mode");
        }
        this.wrapStream.write(bArr, i, i2);
        return null;
    }

    @Override // javax.crypto.CipherSpi
    protected int engineUpdate(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws ShortBufferException {
        if (this.wrapStream == null) {
            throw new IllegalStateException("not supported in a wrapping mode");
        }
        this.wrapStream.write(bArr, i, i2);
        return 0;
    }

    @Override // javax.crypto.CipherSpi
    protected byte[] engineDoFinal(byte[] bArr, int i, int i2) throws IllegalBlockSizeException, BadPaddingException {
        if (this.wrapStream == null) {
            throw new IllegalStateException("not supported in a wrapping mode");
        }
        if (bArr != null) {
            this.wrapStream.write(bArr, i, i2);
        }
        try {
            if (this.forWrapping) {
                try {
                    byte[] wrap = this.wrapEngine.wrap(this.wrapStream.getBuf(), 0, this.wrapStream.size());
                    this.wrapStream.erase();
                    return wrap;
                } catch (Exception e) {
                    throw new IllegalBlockSizeException(e.getMessage());
                }
            }
            try {
                byte[] unwrap = this.wrapEngine.unwrap(this.wrapStream.getBuf(), 0, this.wrapStream.size());
                this.wrapStream.erase();
                return unwrap;
            } catch (InvalidCipherTextException e2) {
                throw new BadPaddingException(e2.getMessage());
            }
        } catch (Throwable th) {
            this.wrapStream.erase();
            throw th;
        }
        this.wrapStream.erase();
        throw th;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0086 A[Catch: all -> 0x00ac, TryCatch #2 {all -> 0x00ac, blocks: (B:7:0x001b, B:9:0x0022, B:17:0x007a, B:19:0x0086, B:20:0x008f, B:21:0x0090, B:13:0x004e, B:11:0x0041, B:12:0x004d, B:15:0x006d, B:16:0x0079), top: B:32:0x001b, inners: #0, #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0090 A[Catch: all -> 0x00ac, TRY_LEAVE, TryCatch #2 {all -> 0x00ac, blocks: (B:7:0x001b, B:9:0x0022, B:17:0x007a, B:19:0x0086, B:20:0x008f, B:21:0x0090, B:13:0x004e, B:11:0x0041, B:12:0x004d, B:15:0x006d, B:16:0x0079), top: B:32:0x001b, inners: #0, #1 }] */
    @Override // javax.crypto.CipherSpi
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    protected int engineDoFinal(byte[] r7, int r8, int r9, byte[] r10, int r11) throws javax.crypto.IllegalBlockSizeException, javax.crypto.BadPaddingException, javax.crypto.ShortBufferException {
        /*
            r6 = this;
            r0 = r6
            org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher$ErasableOutputStream r0 = r0.wrapStream
            if (r0 != 0) goto L11
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            r1 = r0
            java.lang.String r2 = "not supported in a wrapping mode"
            r1.<init>(r2)
            throw r0
        L11:
            r0 = r6
            org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher$ErasableOutputStream r0 = r0.wrapStream
            r1 = r7
            r2 = r8
            r3 = r9
            r0.write(r1, r2, r3)
            r0 = r6
            boolean r0 = r0.forWrapping     // Catch: java.lang.Throwable -> Lac
            if (r0 == 0) goto L4e
            r0 = r6
            org.bouncycastle.crypto.Wrapper r0 = r0.wrapEngine     // Catch: java.lang.Exception -> L3f java.lang.Throwable -> Lac
            r1 = r6
            org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher$ErasableOutputStream r1 = r1.wrapStream     // Catch: java.lang.Exception -> L3f java.lang.Throwable -> Lac
            byte[] r1 = r1.getBuf()     // Catch: java.lang.Exception -> L3f java.lang.Throwable -> Lac
            r2 = 0
            r3 = r6
            org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher$ErasableOutputStream r3 = r3.wrapStream     // Catch: java.lang.Exception -> L3f java.lang.Throwable -> Lac
            int r3 = r3.size()     // Catch: java.lang.Exception -> L3f java.lang.Throwable -> Lac
            byte[] r0 = r0.wrap(r1, r2, r3)     // Catch: java.lang.Exception -> L3f java.lang.Throwable -> Lac
            r12 = r0
            goto L7a
        L3f:
            r13 = move-exception
            javax.crypto.IllegalBlockSizeException r0 = new javax.crypto.IllegalBlockSizeException     // Catch: java.lang.Throwable -> Lac
            r1 = r0
            r2 = r13
            java.lang.String r2 = r2.getMessage()     // Catch: java.lang.Throwable -> Lac
            r1.<init>(r2)     // Catch: java.lang.Throwable -> Lac
            throw r0     // Catch: java.lang.Throwable -> Lac
        L4e:
            r0 = r6
            org.bouncycastle.crypto.Wrapper r0 = r0.wrapEngine     // Catch: org.bouncycastle.crypto.InvalidCipherTextException -> L6b java.lang.Throwable -> Lac
            r1 = r6
            org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher$ErasableOutputStream r1 = r1.wrapStream     // Catch: org.bouncycastle.crypto.InvalidCipherTextException -> L6b java.lang.Throwable -> Lac
            byte[] r1 = r1.getBuf()     // Catch: org.bouncycastle.crypto.InvalidCipherTextException -> L6b java.lang.Throwable -> Lac
            r2 = 0
            r3 = r6
            org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher$ErasableOutputStream r3 = r3.wrapStream     // Catch: org.bouncycastle.crypto.InvalidCipherTextException -> L6b java.lang.Throwable -> Lac
            int r3 = r3.size()     // Catch: org.bouncycastle.crypto.InvalidCipherTextException -> L6b java.lang.Throwable -> Lac
            byte[] r0 = r0.unwrap(r1, r2, r3)     // Catch: org.bouncycastle.crypto.InvalidCipherTextException -> L6b java.lang.Throwable -> Lac
            r12 = r0
            goto L7a
        L6b:
            r13 = move-exception
            javax.crypto.BadPaddingException r0 = new javax.crypto.BadPaddingException     // Catch: java.lang.Throwable -> Lac
            r1 = r0
            r2 = r13
            java.lang.String r2 = r2.getMessage()     // Catch: java.lang.Throwable -> Lac
            r1.<init>(r2)     // Catch: java.lang.Throwable -> Lac
            throw r0     // Catch: java.lang.Throwable -> Lac
        L7a:
            r0 = r11
            r1 = r12
            int r1 = r1.length     // Catch: java.lang.Throwable -> Lac
            int r0 = r0 + r1
            r1 = r10
            int r1 = r1.length     // Catch: java.lang.Throwable -> Lac
            if (r0 <= r1) goto L90
            javax.crypto.ShortBufferException r0 = new javax.crypto.ShortBufferException     // Catch: java.lang.Throwable -> Lac
            r1 = r0
            java.lang.String r2 = "output buffer too short for input."
            r1.<init>(r2)     // Catch: java.lang.Throwable -> Lac
            throw r0     // Catch: java.lang.Throwable -> Lac
        L90:
            r0 = r12
            r1 = 0
            r2 = r10
            r3 = r11
            r4 = r12
            int r4 = r4.length     // Catch: java.lang.Throwable -> Lac
            java.lang.System.arraycopy(r0, r1, r2, r3, r4)     // Catch: java.lang.Throwable -> Lac
            r0 = r12
            int r0 = r0.length     // Catch: java.lang.Throwable -> Lac
            r13 = r0
            r0 = r6
            org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher$ErasableOutputStream r0 = r0.wrapStream
            r0.erase()
            r0 = r13
            return r0
        Lac:
            r14 = move-exception
            r0 = r6
            org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher$ErasableOutputStream r0 = r0.wrapStream
            r0.erase()
            r0 = r14
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher.engineDoFinal(byte[], int, int, byte[], int):int");
    }

    @Override // javax.crypto.CipherSpi
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("Cannot wrap key, null encoding.");
        }
        try {
            return this.wrapEngine == null ? engineDoFinal(encoded, 0, encoded.length) : this.wrapEngine.wrap(encoded, 0, encoded.length);
        } catch (BadPaddingException e) {
            throw new IllegalBlockSizeException(e.getMessage());
        }
    }

    @Override // javax.crypto.CipherSpi
    protected Key engineUnwrap(byte[] bArr, String str, int i) throws InvalidKeyException, NoSuchAlgorithmException {
        try {
            byte[] engineDoFinal = this.wrapEngine == null ? engineDoFinal(bArr, 0, bArr.length) : this.wrapEngine.unwrap(bArr, 0, bArr.length);
            if (i == 3) {
                return new SecretKeySpec(engineDoFinal, str);
            }
            if (str.equals("") && i == 2) {
                try {
                    PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(engineDoFinal);
                    PrivateKey privateKey = BouncyCastleProvider.getPrivateKey(privateKeyInfo);
                    if (privateKey != null) {
                        return privateKey;
                    }
                    throw new InvalidKeyException("algorithm " + privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm() + " not supported");
                } catch (Exception e) {
                    throw new InvalidKeyException("Invalid key encoding.");
                }
            }
            try {
                KeyFactory createKeyFactory = this.helper.createKeyFactory(str);
                if (i == 1) {
                    return createKeyFactory.generatePublic(new X509EncodedKeySpec(engineDoFinal));
                }
                if (i == 2) {
                    return createKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(engineDoFinal));
                }
                throw new InvalidKeyException("Unknown key type " + i);
            } catch (NoSuchProviderException e2) {
                throw new InvalidKeyException("Unknown key type " + e2.getMessage());
            } catch (InvalidKeySpecException e3) {
                throw new InvalidKeyException("Unknown key type " + e3.getMessage());
            }
        } catch (BadPaddingException e4) {
            throw new InvalidKeyException(e4.getMessage());
        } catch (IllegalBlockSizeException e5) {
            throw new InvalidKeyException(e5.getMessage());
        } catch (InvalidCipherTextException e6) {
            throw new InvalidKeyException(e6.getMessage());
        }
    }
}