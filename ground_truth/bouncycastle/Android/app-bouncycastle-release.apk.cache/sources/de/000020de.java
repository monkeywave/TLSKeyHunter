package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyEncoder;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.agreement.XDHBasicAgreement;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.parsers.XIESPublicKeyParser;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.IESUtil;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class IESCipher extends BaseCipherSpi {
    private ByteArrayOutputStream buffer;
    private boolean dhaesMode;
    private IESEngine engine;
    private AlgorithmParameters engineParam;
    private IESParameterSpec engineSpec;
    private final JcaJceHelper helper;
    private int ivLength;
    private AsymmetricKeyParameter key;
    private AsymmetricKeyParameter otherKeyParameter;
    private SecureRandom random;
    private int state;

    /* loaded from: classes2.dex */
    public static class XIES extends IESCipher {
        public XIES() {
            this(DigestFactory.createSHA1(), DigestFactory.createSHA1());
        }

        public XIES(Digest digest, Digest digest2) {
            super(new IESEngine(new XDHBasicAgreement(), new KDF2BytesGenerator(digest), new HMac(digest2)));
        }
    }

    /* loaded from: classes2.dex */
    public static class XIESwithAESCBC extends XIESwithCipher {
        public XIESwithAESCBC() {
            super(CBCBlockCipher.newInstance(AESEngine.newInstance()), 16);
        }
    }

    /* loaded from: classes2.dex */
    public static class XIESwithCipher extends IESCipher {
        public XIESwithCipher(BlockCipher blockCipher, int i) {
            this(blockCipher, i, DigestFactory.createSHA1(), DigestFactory.createSHA1());
        }

        public XIESwithCipher(BlockCipher blockCipher, int i, Digest digest, Digest digest2) {
            super(new IESEngine(new XDHBasicAgreement(), new KDF2BytesGenerator(digest), new HMac(digest2), new PaddedBufferedBlockCipher(blockCipher)), i);
        }
    }

    /* loaded from: classes2.dex */
    public static class XIESwithDESedeCBC extends XIESwithCipher {
        public XIESwithDESedeCBC() {
            super(CBCBlockCipher.newInstance(new DESedeEngine()), 8);
        }
    }

    /* loaded from: classes2.dex */
    public static class XIESwithSHA256 extends XIES {
        public XIESwithSHA256() {
            super(DigestFactory.createSHA256(), DigestFactory.createSHA256());
        }
    }

    /* loaded from: classes2.dex */
    public static class XIESwithSHA256andAESCBC extends XIESwithCipher {
        public XIESwithSHA256andAESCBC() {
            super(CBCBlockCipher.newInstance(AESEngine.newInstance()), 16, DigestFactory.createSHA256(), DigestFactory.createSHA256());
        }
    }

    /* loaded from: classes2.dex */
    public static class XIESwithSHA256andDESedeCBC extends XIESwithCipher {
        public XIESwithSHA256andDESedeCBC() {
            super(CBCBlockCipher.newInstance(new DESedeEngine()), 8, DigestFactory.createSHA256(), DigestFactory.createSHA256());
        }
    }

    /* loaded from: classes2.dex */
    public static class XIESwithSHA384 extends XIES {
        public XIESwithSHA384() {
            super(DigestFactory.createSHA384(), DigestFactory.createSHA384());
        }
    }

    /* loaded from: classes2.dex */
    public static class XIESwithSHA384andAESCBC extends XIESwithCipher {
        public XIESwithSHA384andAESCBC() {
            super(CBCBlockCipher.newInstance(AESEngine.newInstance()), 16, DigestFactory.createSHA384(), DigestFactory.createSHA384());
        }
    }

    /* loaded from: classes2.dex */
    public static class XIESwithSHA384andDESedeCBC extends XIESwithCipher {
        public XIESwithSHA384andDESedeCBC() {
            super(CBCBlockCipher.newInstance(new DESedeEngine()), 8, DigestFactory.createSHA384(), DigestFactory.createSHA384());
        }
    }

    /* loaded from: classes2.dex */
    public static class XIESwithSHA512 extends XIES {
        public XIESwithSHA512() {
            super(DigestFactory.createSHA512(), DigestFactory.createSHA512());
        }
    }

    /* loaded from: classes2.dex */
    public static class XIESwithSHA512andAESCBC extends XIESwithCipher {
        public XIESwithSHA512andAESCBC() {
            super(CBCBlockCipher.newInstance(AESEngine.newInstance()), 16, DigestFactory.createSHA512(), DigestFactory.createSHA512());
        }
    }

    /* loaded from: classes2.dex */
    public static class XIESwithSHA512andDESedeCBC extends XIESwithCipher {
        public XIESwithSHA512andDESedeCBC() {
            super(CBCBlockCipher.newInstance(new DESedeEngine()), 8, DigestFactory.createSHA512(), DigestFactory.createSHA512());
        }
    }

    public IESCipher(IESEngine iESEngine) {
        this.helper = new BCJcaJceHelper();
        this.state = -1;
        this.buffer = new ByteArrayOutputStream();
        this.engineParam = null;
        this.engineSpec = null;
        this.dhaesMode = false;
        this.otherKeyParameter = null;
        this.engine = iESEngine;
        this.ivLength = 0;
    }

    public IESCipher(IESEngine iESEngine, int i) {
        this.helper = new BCJcaJceHelper();
        this.state = -1;
        this.buffer = new ByteArrayOutputStream();
        this.engineParam = null;
        this.engineSpec = null;
        this.dhaesMode = false;
        this.otherKeyParameter = null;
        this.engine = iESEngine;
        this.ivLength = i;
    }

    @Override // javax.crypto.CipherSpi
    public int engineDoFinal(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] engineDoFinal = engineDoFinal(bArr, i, i2);
        System.arraycopy(engineDoFinal, 0, bArr2, i3, engineDoFinal.length);
        return engineDoFinal.length;
    }

    @Override // javax.crypto.CipherSpi
    public byte[] engineDoFinal(byte[] bArr, int i, int i2) throws IllegalBlockSizeException, BadPaddingException {
        if (i2 != 0) {
            this.buffer.write(bArr, i, i2);
        }
        byte[] byteArray = this.buffer.toByteArray();
        this.buffer.reset();
        CipherParameters iESWithCipherParameters = new IESWithCipherParameters(this.engineSpec.getDerivationV(), this.engineSpec.getEncodingV(), this.engineSpec.getMacKeySize(), this.engineSpec.getCipherKeySize());
        byte[] nonce = this.engineSpec.getNonce();
        if (nonce != null) {
            iESWithCipherParameters = new ParametersWithIV(iESWithCipherParameters, nonce);
        }
        AsymmetricKeyParameter asymmetricKeyParameter = this.otherKeyParameter;
        if (asymmetricKeyParameter != null) {
            try {
                int i3 = this.state;
                if (i3 != 1 && i3 != 3) {
                    this.engine.init(false, this.key, asymmetricKeyParameter, iESWithCipherParameters);
                    return this.engine.processBlock(byteArray, 0, byteArray.length);
                }
                this.engine.init(true, asymmetricKeyParameter, this.key, iESWithCipherParameters);
                return this.engine.processBlock(byteArray, 0, byteArray.length);
            } catch (Exception e) {
                throw new BadBlockException("unable to process block", e);
            }
        }
        AsymmetricKeyParameter asymmetricKeyParameter2 = this.key;
        final boolean z = (asymmetricKeyParameter2 instanceof X25519PublicKeyParameters) || (asymmetricKeyParameter2 instanceof X25519PrivateKeyParameters);
        int i4 = z ? 256 : 448;
        int i5 = this.state;
        if (i5 == 1 || i5 == 3) {
            AsymmetricCipherKeyPairGenerator x25519KeyPairGenerator = z ? new X25519KeyPairGenerator() : new X448KeyPairGenerator();
            x25519KeyPairGenerator.init(new KeyGenerationParameters(this.random, i4));
            try {
                this.engine.init(this.key, iESWithCipherParameters, new EphemeralKeyPairGenerator(x25519KeyPairGenerator, new KeyEncoder() { // from class: org.bouncycastle.jcajce.provider.asymmetric.edec.IESCipher.1
                    @Override // org.bouncycastle.crypto.KeyEncoder
                    public byte[] getEncoded(AsymmetricKeyParameter asymmetricKeyParameter3) {
                        return z ? ((X25519PublicKeyParameters) asymmetricKeyParameter3).getEncoded() : ((X448PublicKeyParameters) asymmetricKeyParameter3).getEncoded();
                    }
                }));
                return this.engine.processBlock(byteArray, 0, byteArray.length);
            } catch (Exception e2) {
                throw new BadBlockException("unable to process block", e2);
            }
        } else if (i5 == 2 || i5 == 4) {
            try {
                this.engine.init(asymmetricKeyParameter2, iESWithCipherParameters, new XIESPublicKeyParser(z));
                return this.engine.processBlock(byteArray, 0, byteArray.length);
            } catch (InvalidCipherTextException e3) {
                throw new BadBlockException("unable to process block", e3);
            }
        } else {
            throw new IllegalStateException("cipher not initialised");
        }
    }

    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi, javax.crypto.CipherSpi
    public int engineGetBlockSize() {
        BufferedBlockCipher cipher = this.engine.getCipher();
        if (cipher == null) {
            return 0;
        }
        return cipher.getBlockSize();
    }

    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi, javax.crypto.CipherSpi
    public byte[] engineGetIV() {
        IESParameterSpec iESParameterSpec = this.engineSpec;
        if (iESParameterSpec != null) {
            return iESParameterSpec.getNonce();
        }
        return null;
    }

    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi, javax.crypto.CipherSpi
    public int engineGetKeySize(Key key) {
        if (key instanceof XDHKey) {
            String algorithm = ((XDHKey) key).getAlgorithm();
            if (XDHParameterSpec.X25519.equalsIgnoreCase(algorithm)) {
                return 256;
            }
            if (XDHParameterSpec.X448.equalsIgnoreCase(algorithm)) {
                return 448;
            }
            throw new IllegalArgumentException("unknown XDH key algorithm " + algorithm);
        }
        throw new IllegalArgumentException("not an XDH key");
    }

    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi, javax.crypto.CipherSpi
    public int engineGetOutputSize(int i) {
        BufferedBlockCipher cipher;
        if (this.key != null) {
            int macSize = this.engine.getMac().getMacSize();
            int fieldSize = this.otherKeyParameter == null ? ((((ECKeyParameters) this.key).getParameters().getCurve().getFieldSize() + 7) / 8) * 2 : 0;
            int size = this.buffer.size() + i;
            if (this.engine.getCipher() != null) {
                int i2 = this.state;
                if (i2 == 1 || i2 == 3) {
                    cipher = this.engine.getCipher();
                } else if (i2 != 2 && i2 != 4) {
                    throw new IllegalStateException("cipher not initialised");
                } else {
                    cipher = this.engine.getCipher();
                    size = (size - macSize) - fieldSize;
                }
                size = cipher.getOutputSize(size);
            }
            int i3 = this.state;
            if (i3 == 1 || i3 == 3) {
                return macSize + fieldSize + size;
            }
            if (i3 == 2 || i3 == 4) {
                return size;
            }
            throw new IllegalStateException("cipher not initialised");
        }
        throw new IllegalStateException("cipher not initialised");
    }

    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi, javax.crypto.CipherSpi
    public AlgorithmParameters engineGetParameters() {
        if (this.engineParam == null && this.engineSpec != null) {
            try {
                AlgorithmParameters createAlgorithmParameters = this.helper.createAlgorithmParameters("IES");
                this.engineParam = createAlgorithmParameters;
                createAlgorithmParameters.init(this.engineSpec);
            } catch (Exception e) {
                throw new RuntimeException(e.toString());
            }
        }
        return this.engineParam;
    }

    @Override // javax.crypto.CipherSpi
    public void engineInit(int i, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec parameterSpec;
        if (algorithmParameters != null) {
            try {
                parameterSpec = algorithmParameters.getParameterSpec(IESParameterSpec.class);
            } catch (Exception e) {
                throw new InvalidAlgorithmParameterException("cannot recognise parameters: " + e.toString());
            }
        } else {
            parameterSpec = null;
        }
        this.engineParam = algorithmParameters;
        engineInit(i, key, parameterSpec, secureRandom);
    }

    @Override // javax.crypto.CipherSpi
    public void engineInit(int i, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        try {
            AlgorithmParameterSpec algorithmParameterSpec = null;
            engineInit(i, key, (AlgorithmParameterSpec) null, secureRandom);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException("cannot handle supplied parameter spec: " + e.getMessage());
        }
    }

    @Override // javax.crypto.CipherSpi
    public void engineInit(int i, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException {
        IESParameterSpec iESParameterSpec;
        AsymmetricKeyParameter generatePublicKeyParameter;
        this.otherKeyParameter = null;
        if (algorithmParameterSpec == null && this.ivLength == 0) {
            iESParameterSpec = IESUtil.guessParameterSpec(this.engine.getCipher(), null);
        } else if (!(algorithmParameterSpec instanceof IESParameterSpec)) {
            throw new InvalidAlgorithmParameterException("must be passed IES parameters");
        } else {
            iESParameterSpec = (IESParameterSpec) algorithmParameterSpec;
        }
        this.engineSpec = iESParameterSpec;
        byte[] nonce = this.engineSpec.getNonce();
        int i2 = this.ivLength;
        if (i2 != 0 && (nonce == null || nonce.length != i2)) {
            throw new InvalidAlgorithmParameterException("NONCE in IES Parameters needs to be " + this.ivLength + " bytes long");
        }
        if (i == 1 || i == 3) {
            if (!(key instanceof PublicKey)) {
                throw new InvalidKeyException("must be passed recipient's public XDH key for encryption");
            }
            generatePublicKeyParameter = EdECUtil.generatePublicKeyParameter((PublicKey) key);
        } else if (i != 2 && i != 4) {
            throw new InvalidKeyException("must be passed XDH key");
        } else {
            if (!(key instanceof PrivateKey)) {
                throw new InvalidKeyException("must be passed recipient's private XDH key for decryption");
            }
            generatePublicKeyParameter = EdECUtil.generatePrivateKeyParameter((PrivateKey) key);
        }
        this.key = generatePublicKeyParameter;
        this.random = secureRandom;
        this.state = i;
        this.buffer.reset();
    }

    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi, javax.crypto.CipherSpi
    public void engineSetMode(String str) throws NoSuchAlgorithmException {
        boolean z;
        String upperCase = Strings.toUpperCase(str);
        if (upperCase.equals("NONE")) {
            z = false;
        } else if (!upperCase.equals("DHAES")) {
            throw new IllegalArgumentException("can't support mode " + str);
        } else {
            z = true;
        }
        this.dhaesMode = z;
    }

    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi, javax.crypto.CipherSpi
    public void engineSetPadding(String str) throws NoSuchPaddingException {
        String upperCase = Strings.toUpperCase(str);
        if (!upperCase.equals("NOPADDING") && !upperCase.equals("PKCS5PADDING") && !upperCase.equals("PKCS7PADDING")) {
            throw new NoSuchPaddingException("padding not available with IESCipher");
        }
    }

    @Override // javax.crypto.CipherSpi
    public int engineUpdate(byte[] bArr, int i, int i2, byte[] bArr2, int i3) {
        this.buffer.write(bArr, i, i2);
        return 0;
    }

    @Override // javax.crypto.CipherSpi
    public byte[] engineUpdate(byte[] bArr, int i, int i2) {
        this.buffer.write(bArr, i, i2);
        return null;
    }
}