package org.openjsse.sun.security.ssl;

import java.nio.ByteBuffer;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.Authenticator;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher.class */
public enum SSLCipher {
    B_NULL("NULL", CipherType.NULL_CIPHER, 0, 0, 0, 0, true, true, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new NullReadCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_NONE), new AbstractMap.SimpleImmutableEntry(new NullReadCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_13)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new NullWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_NONE), new AbstractMap.SimpleImmutableEntry(new NullWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_13)}),
    B_RC4_40("RC4", CipherType.STREAM_CIPHER, 5, 16, 0, 0, true, true, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new StreamReadCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_10)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new StreamWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_10)}),
    B_RC2_40("RC2", CipherType.BLOCK_CIPHER, 5, 16, 8, 0, false, true, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new StreamReadCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_10)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new StreamWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_10)}),
    B_DES_40("DES/CBC/NoPadding", CipherType.BLOCK_CIPHER, 5, 8, 8, 0, true, true, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T10BlockReadCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_10)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T10BlockWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_10)}),
    B_RC4_128("RC4", CipherType.STREAM_CIPHER, 16, 16, 0, 0, true, false, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new StreamReadCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_12)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new StreamWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_12)}),
    B_DES("DES/CBC/NoPadding", CipherType.BLOCK_CIPHER, 8, 8, 8, 0, true, false, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T10BlockReadCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_10), new AbstractMap.SimpleImmutableEntry(new T11BlockReadCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_11)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T10BlockWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_10), new AbstractMap.SimpleImmutableEntry(new T11BlockWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_11)}),
    B_3DES("DESede/CBC/NoPadding", CipherType.BLOCK_CIPHER, 24, 24, 8, 0, true, false, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T10BlockReadCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_10), new AbstractMap.SimpleImmutableEntry(new T11BlockReadCipherGenerator(), ProtocolVersion.PROTOCOLS_11_12)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T10BlockWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_10), new AbstractMap.SimpleImmutableEntry(new T11BlockWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_11_12)}),
    B_IDEA("IDEA", CipherType.BLOCK_CIPHER, 16, 16, 8, 0, false, false, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(null, ProtocolVersion.PROTOCOLS_TO_12)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(null, ProtocolVersion.PROTOCOLS_TO_12)}),
    B_AES_128("AES/CBC/NoPadding", CipherType.BLOCK_CIPHER, 16, 16, 16, 0, true, false, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T10BlockReadCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_10), new AbstractMap.SimpleImmutableEntry(new T11BlockReadCipherGenerator(), ProtocolVersion.PROTOCOLS_11_12)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T10BlockWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_10), new AbstractMap.SimpleImmutableEntry(new T11BlockWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_11_12)}),
    B_AES_256("AES/CBC/NoPadding", CipherType.BLOCK_CIPHER, 32, 32, 16, 0, true, false, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T10BlockReadCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_10), new AbstractMap.SimpleImmutableEntry(new T11BlockReadCipherGenerator(), ProtocolVersion.PROTOCOLS_11_12)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T10BlockWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_TO_10), new AbstractMap.SimpleImmutableEntry(new T11BlockWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_11_12)}),
    B_AES_128_GCM("AES/GCM/NoPadding", CipherType.AEAD_CIPHER, 16, 16, 12, 4, true, false, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T12GcmReadCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_12)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T12GcmWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_12)}),
    B_AES_256_GCM("AES/GCM/NoPadding", CipherType.AEAD_CIPHER, 32, 32, 12, 4, true, false, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T12GcmReadCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_12)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T12GcmWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_12)}),
    B_AES_128_GCM_IV("AES/GCM/NoPadding", CipherType.AEAD_CIPHER, 16, 16, 12, 0, true, false, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T13GcmReadCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_13)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T13GcmWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_13)}),
    B_AES_256_GCM_IV("AES/GCM/NoPadding", CipherType.AEAD_CIPHER, 32, 32, 12, 0, true, false, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T13GcmReadCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_13)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T13GcmWriteCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_13)}),
    B_CC20_P1305("ChaCha20-Poly1305", CipherType.AEAD_CIPHER, 32, 32, 12, 12, true, false, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T12CC20P1305ReadCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_12), new AbstractMap.SimpleImmutableEntry(new T13CC20P1305ReadCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_13)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(new T12CC20P1305WriteCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_12), new AbstractMap.SimpleImmutableEntry(new T13CC20P1305WriteCipherGenerator(), ProtocolVersion.PROTOCOLS_OF_13)});
    
    final String description;
    final String transformation;
    final String algorithm;
    final boolean allowed;
    final int keySize;
    final int expandedKeySize;
    final int ivSize;
    final int fixedIvSize;
    final boolean exportable;
    final CipherType cipherType;
    final int tagSize = 16;
    private final boolean isAvailable;
    private final Map.Entry<ReadCipherGenerator, ProtocolVersion[]>[] readCipherGenerators;
    private final Map.Entry<WriteCipherGenerator, ProtocolVersion[]>[] writeCipherGenerators;
    private static final HashMap<String, Long> cipherLimits = new HashMap<>();
    static final String[] tag = {"KEYUPDATE"};

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$ReadCipherGenerator.class */
    public interface ReadCipherGenerator {
        SSLReadCipher createCipher(SSLCipher sSLCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String str, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws GeneralSecurityException;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$WriteCipherGenerator.class */
    public interface WriteCipherGenerator {
        SSLWriteCipher createCipher(SSLCipher sSLCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String str, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws GeneralSecurityException;
    }

    static {
        long size;
        String prop = (String) AccessController.doPrivileged(new PrivilegedAction<String>() { // from class: org.openjsse.sun.security.ssl.SSLCipher.1
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // java.security.PrivilegedAction
            public String run() {
                return Security.getProperty("jdk.tls.keyLimits");
            }
        });
        if (prop != null) {
            String[] propvalue = prop.split(",");
            for (String entry : propvalue) {
                String[] values = entry.trim().toUpperCase().split(" ");
                if (!values[1].contains(tag[0])) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                        SSLLogger.fine("jdk.tls.keyLimits:  Unknown action:  " + entry, new Object[0]);
                    }
                } else {
                    int i = values[2].indexOf("^");
                    if (i >= 0) {
                        try {
                            size = (long) Math.pow(2.0d, Integer.parseInt(values[2].substring(i + 1)));
                        } catch (NumberFormatException e) {
                            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                                SSLLogger.fine("jdk.tls.keyLimits:  " + e.getMessage() + ":  " + entry, new Object[0]);
                            }
                        }
                    } else {
                        size = Long.parseLong(values[2]);
                    }
                    if (size < 1 || size > 4611686018427387904L) {
                        throw new NumberFormatException("Length exceeded limits");
                        break;
                    }
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                        SSLLogger.fine("jdk.tls.keyLimits:  entry = " + entry + ". " + values[0] + ":" + tag[0] + " = " + size, new Object[0]);
                    }
                    cipherLimits.put(values[0] + ":" + tag[0], Long.valueOf(size));
                }
            }
        }
    }

    SSLCipher(String transformation, CipherType cipherType, int keySize, int expandedKeySize, int ivSize, int fixedIvSize, boolean allowed, boolean exportable, Map.Entry[] entryArr, Map.Entry[] entryArr2) {
        this.transformation = transformation;
        String[] splits = transformation.split("/");
        this.algorithm = splits[0];
        this.cipherType = cipherType;
        this.description = this.algorithm + "/" + (keySize << 3);
        this.keySize = keySize;
        this.ivSize = ivSize;
        this.fixedIvSize = fixedIvSize;
        this.allowed = allowed;
        this.expandedKeySize = expandedKeySize;
        this.exportable = exportable;
        this.isAvailable = allowed && isUnlimited(keySize, transformation) && isTransformationAvailable(transformation);
        this.readCipherGenerators = entryArr;
        this.writeCipherGenerators = entryArr2;
    }

    private static boolean isTransformationAvailable(String transformation) {
        if (transformation.equals("NULL")) {
            return true;
        }
        try {
            JsseJce.getCipher(transformation);
            return true;
        } catch (NoSuchAlgorithmException e) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.fine("Transformation " + transformation + " is not available.", new Object[0]);
                return false;
            }
            return false;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLReadCipher createReadCipher(Authenticator authenticator, ProtocolVersion protocolVersion, SecretKey key, IvParameterSpec iv, SecureRandom random) throws GeneralSecurityException {
        Map.Entry<ReadCipherGenerator, ProtocolVersion[]>[] entryArr;
        ProtocolVersion[] value;
        if (this.writeCipherGenerators.length == 0) {
            return null;
        }
        ReadCipherGenerator wcg = null;
        for (Map.Entry<ReadCipherGenerator, ProtocolVersion[]> me : this.readCipherGenerators) {
            for (ProtocolVersion pv : me.getValue()) {
                if (protocolVersion == pv) {
                    wcg = me.getKey();
                }
            }
        }
        if (wcg != null) {
            return wcg.createCipher(this, authenticator, protocolVersion, this.transformation, key, iv, random);
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLWriteCipher createWriteCipher(Authenticator authenticator, ProtocolVersion protocolVersion, SecretKey key, IvParameterSpec iv, SecureRandom random) throws GeneralSecurityException {
        Map.Entry<WriteCipherGenerator, ProtocolVersion[]>[] entryArr;
        ProtocolVersion[] value;
        if (this.readCipherGenerators.length == 0) {
            return null;
        }
        WriteCipherGenerator rcg = null;
        for (Map.Entry<WriteCipherGenerator, ProtocolVersion[]> me : this.writeCipherGenerators) {
            for (ProtocolVersion pv : me.getValue()) {
                if (protocolVersion == pv) {
                    rcg = me.getKey();
                }
            }
        }
        if (rcg != null) {
            return rcg.createCipher(this, authenticator, protocolVersion, this.transformation, key, iv, random);
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isAvailable() {
        return this.isAvailable;
    }

    private static boolean isUnlimited(int keySize, String transformation) {
        int keySizeInBits = keySize * 8;
        if (keySizeInBits > 128) {
            try {
                if (Cipher.getMaxAllowedKeyLength(transformation) < keySizeInBits) {
                    return false;
                }
                return true;
            } catch (Exception e) {
                return false;
            }
        }
        return true;
    }

    @Override // java.lang.Enum
    public String toString() {
        return this.description;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$SSLReadCipher.class */
    public static abstract class SSLReadCipher {
        final Authenticator authenticator;
        final ProtocolVersion protocolVersion;
        boolean keyLimitEnabled = false;
        long keyLimitCountdown = 0;
        SecretKey baseSecret;

        /* JADX INFO: Access modifiers changed from: package-private */
        public abstract Plaintext decrypt(byte b, ByteBuffer byteBuffer, byte[] bArr) throws GeneralSecurityException;

        /* JADX INFO: Access modifiers changed from: package-private */
        public abstract int estimateFragmentSize(int i, int i2);

        SSLReadCipher(Authenticator authenticator, ProtocolVersion protocolVersion) {
            this.authenticator = authenticator;
            this.protocolVersion = protocolVersion;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static final SSLReadCipher nullTlsReadCipher() {
            try {
                return SSLCipher.B_NULL.createReadCipher(Authenticator.nullTlsMac(), ProtocolVersion.NONE, null, null, null);
            } catch (GeneralSecurityException gse) {
                throw new RuntimeException("Cannot create NULL SSLCipher", gse);
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static final SSLReadCipher nullDTlsReadCipher() {
            try {
                return SSLCipher.B_NULL.createReadCipher(Authenticator.nullDtlsMac(), ProtocolVersion.NONE, null, null, null);
            } catch (GeneralSecurityException gse) {
                throw new RuntimeException("Cannot create NULL SSLCipher", gse);
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public void dispose() {
        }

        boolean isNullCipher() {
            return false;
        }

        public boolean atKeyLimit() {
            if (this.keyLimitCountdown >= 0) {
                return false;
            }
            this.keyLimitEnabled = false;
            return true;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$SSLWriteCipher.class */
    public static abstract class SSLWriteCipher {
        final Authenticator authenticator;
        final ProtocolVersion protocolVersion;
        boolean keyLimitEnabled = false;
        long keyLimitCountdown = 0;
        SecretKey baseSecret;

        /* JADX INFO: Access modifiers changed from: package-private */
        public abstract int encrypt(byte b, ByteBuffer byteBuffer);

        /* JADX INFO: Access modifiers changed from: package-private */
        public abstract int getExplicitNonceSize();

        /* JADX INFO: Access modifiers changed from: package-private */
        public abstract int calculateFragmentSize(int i, int i2);

        /* JADX INFO: Access modifiers changed from: package-private */
        public abstract int calculatePacketSize(int i, int i2);

        SSLWriteCipher(Authenticator authenticator, ProtocolVersion protocolVersion) {
            this.authenticator = authenticator;
            this.protocolVersion = protocolVersion;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static final SSLWriteCipher nullTlsWriteCipher() {
            try {
                return SSLCipher.B_NULL.createWriteCipher(Authenticator.nullTlsMac(), ProtocolVersion.NONE, null, null, null);
            } catch (GeneralSecurityException gse) {
                throw new RuntimeException("Cannot create NULL SSL write Cipher", gse);
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static final SSLWriteCipher nullDTlsWriteCipher() {
            try {
                return SSLCipher.B_NULL.createWriteCipher(Authenticator.nullDtlsMac(), ProtocolVersion.NONE, null, null, null);
            } catch (GeneralSecurityException gse) {
                throw new RuntimeException("Cannot create NULL SSL write Cipher", gse);
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public void dispose() {
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public boolean isCBCMode() {
            return false;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public boolean isNullCipher() {
            return false;
        }

        public boolean atKeyLimit() {
            if (this.keyLimitCountdown >= 0) {
                return false;
            }
            this.keyLimitEnabled = false;
            return true;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$NullReadCipherGenerator.class */
    private static final class NullReadCipherGenerator implements ReadCipherGenerator {
        private NullReadCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.ReadCipherGenerator
        public SSLReadCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new NullReadCipher(authenticator, protocolVersion);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$NullReadCipherGenerator$NullReadCipher.class */
        static final class NullReadCipher extends SSLReadCipher {
            NullReadCipher(Authenticator authenticator, ProtocolVersion protocolVersion) {
                super(authenticator, protocolVersion);
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public Plaintext decrypt(byte contentType, ByteBuffer bb, byte[] sequence) throws GeneralSecurityException {
                Authenticator.MAC signer = (Authenticator.MAC) this.authenticator;
                if (signer.macAlg().size != 0) {
                    SSLCipher.checkStreamMac(signer, bb, contentType, sequence);
                } else {
                    this.authenticator.increaseSequenceNumber();
                }
                return new Plaintext(contentType, ProtocolVersion.NONE.major, ProtocolVersion.NONE.minor, -1, -1L, bb.slice());
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            int estimateFragmentSize(int packetSize, int headerSize) {
                int macLen = ((Authenticator.MAC) this.authenticator).macAlg().size;
                return (packetSize - headerSize) - macLen;
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            boolean isNullCipher() {
                return true;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$NullWriteCipherGenerator.class */
    private static final class NullWriteCipherGenerator implements WriteCipherGenerator {
        private NullWriteCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.WriteCipherGenerator
        public SSLWriteCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new NullWriteCipher(authenticator, protocolVersion);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$NullWriteCipherGenerator$NullWriteCipher.class */
        static final class NullWriteCipher extends SSLWriteCipher {
            NullWriteCipher(Authenticator authenticator, ProtocolVersion protocolVersion) {
                super(authenticator, protocolVersion);
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int encrypt(byte contentType, ByteBuffer bb) {
                Authenticator.MAC signer = (Authenticator.MAC) this.authenticator;
                if (signer.macAlg().size != 0) {
                    SSLCipher.addMac(signer, bb, contentType);
                } else {
                    this.authenticator.increaseSequenceNumber();
                }
                int len = bb.remaining();
                bb.position(bb.limit());
                return len;
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            int getExplicitNonceSize() {
                return 0;
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            int calculateFragmentSize(int packetLimit, int headerSize) {
                int macLen = ((Authenticator.MAC) this.authenticator).macAlg().size;
                return (packetLimit - headerSize) - macLen;
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            int calculatePacketSize(int fragmentSize, int headerSize) {
                int macLen = ((Authenticator.MAC) this.authenticator).macAlg().size;
                return fragmentSize + headerSize + macLen;
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            boolean isNullCipher() {
                return true;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$StreamReadCipherGenerator.class */
    private static final class StreamReadCipherGenerator implements ReadCipherGenerator {
        private StreamReadCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.ReadCipherGenerator
        public SSLReadCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new StreamReadCipher(authenticator, protocolVersion, algorithm, key, params, random);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$StreamReadCipherGenerator$StreamReadCipher.class */
        static final class StreamReadCipher extends SSLReadCipher {
            private final Cipher cipher;

            StreamReadCipher(Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = JsseJce.getCipher(algorithm);
                this.cipher.init(2, key, params, random);
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public Plaintext decrypt(byte contentType, ByteBuffer bb, byte[] sequence) throws GeneralSecurityException {
                int len = bb.remaining();
                int pos = bb.position();
                ByteBuffer dup = bb.duplicate();
                try {
                    if (len != this.cipher.update(dup, bb)) {
                        throw new RuntimeException("Unexpected number of plaintext bytes");
                    }
                    if (bb.position() != dup.position()) {
                        throw new RuntimeException("Unexpected ByteBuffer position");
                    }
                    bb.position(pos);
                    if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                        SSLLogger.fine("Plaintext after DECRYPTION", bb.duplicate());
                    }
                    Authenticator.MAC signer = (Authenticator.MAC) this.authenticator;
                    if (signer.macAlg().size != 0) {
                        SSLCipher.checkStreamMac(signer, bb, contentType, sequence);
                    } else {
                        this.authenticator.increaseSequenceNumber();
                    }
                    return new Plaintext(contentType, ProtocolVersion.NONE.major, ProtocolVersion.NONE.minor, -1, -1L, bb.slice());
                } catch (ShortBufferException sbe) {
                    throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName(), sbe);
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public void dispose() {
                if (this.cipher != null) {
                    try {
                        this.cipher.doFinal();
                    } catch (Exception e) {
                    }
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public int estimateFragmentSize(int packetSize, int headerSize) {
                int macLen = ((Authenticator.MAC) this.authenticator).macAlg().size;
                return (packetSize - headerSize) - macLen;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$StreamWriteCipherGenerator.class */
    private static final class StreamWriteCipherGenerator implements WriteCipherGenerator {
        private StreamWriteCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.WriteCipherGenerator
        public SSLWriteCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new StreamWriteCipher(authenticator, protocolVersion, algorithm, key, params, random);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$StreamWriteCipherGenerator$StreamWriteCipher.class */
        static final class StreamWriteCipher extends SSLWriteCipher {
            private final Cipher cipher;

            StreamWriteCipher(Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = JsseJce.getCipher(algorithm);
                this.cipher.init(1, key, params, random);
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int encrypt(byte contentType, ByteBuffer bb) {
                Authenticator.MAC signer = (Authenticator.MAC) this.authenticator;
                if (signer.macAlg().size != 0) {
                    SSLCipher.addMac(signer, bb, contentType);
                } else {
                    this.authenticator.increaseSequenceNumber();
                }
                if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                    SSLLogger.finest("Padded plaintext before ENCRYPTION", bb.duplicate());
                }
                int len = bb.remaining();
                ByteBuffer dup = bb.duplicate();
                try {
                    if (len != this.cipher.update(dup, bb)) {
                        throw new RuntimeException("Unexpected number of plaintext bytes");
                    }
                    if (bb.position() != dup.position()) {
                        throw new RuntimeException("Unexpected ByteBuffer position");
                    }
                    return len;
                } catch (ShortBufferException sbe) {
                    throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName(), sbe);
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public void dispose() {
                if (this.cipher != null) {
                    try {
                        this.cipher.doFinal();
                    } catch (Exception e) {
                    }
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int getExplicitNonceSize() {
                return 0;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int calculateFragmentSize(int packetLimit, int headerSize) {
                int macLen = ((Authenticator.MAC) this.authenticator).macAlg().size;
                return (packetLimit - headerSize) - macLen;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int calculatePacketSize(int fragmentSize, int headerSize) {
                int macLen = ((Authenticator.MAC) this.authenticator).macAlg().size;
                return fragmentSize + headerSize + macLen;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T10BlockReadCipherGenerator.class */
    private static final class T10BlockReadCipherGenerator implements ReadCipherGenerator {
        private T10BlockReadCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.ReadCipherGenerator
        public SSLReadCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new BlockReadCipher(authenticator, protocolVersion, algorithm, key, params, random);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T10BlockReadCipherGenerator$BlockReadCipher.class */
        static final class BlockReadCipher extends SSLReadCipher {
            private final Cipher cipher;

            BlockReadCipher(Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = JsseJce.getCipher(algorithm);
                this.cipher.init(2, key, params, random);
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public Plaintext decrypt(byte contentType, ByteBuffer bb, byte[] sequence) throws GeneralSecurityException {
                BadPaddingException reservedBPE = null;
                Authenticator.MAC signer = (Authenticator.MAC) this.authenticator;
                int cipheredLength = bb.remaining();
                int tagLen = signer.macAlg().size;
                if (tagLen != 0 && !sanityCheck(tagLen, bb.remaining())) {
                    reservedBPE = new BadPaddingException("ciphertext sanity check failed");
                }
                int len = bb.remaining();
                int pos = bb.position();
                ByteBuffer dup = bb.duplicate();
                try {
                    if (len != this.cipher.update(dup, bb)) {
                        throw new RuntimeException("Unexpected number of plaintext bytes");
                    }
                    if (bb.position() != dup.position()) {
                        throw new RuntimeException("Unexpected ByteBuffer position");
                    }
                    if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                        SSLLogger.fine("Padded plaintext after DECRYPTION", bb.duplicate().position(pos));
                    }
                    int blockSize = this.cipher.getBlockSize();
                    bb.position(pos);
                    try {
                        SSLCipher.removePadding(bb, tagLen, blockSize, this.protocolVersion);
                    } catch (BadPaddingException bpe) {
                        if (reservedBPE == null) {
                            reservedBPE = bpe;
                        }
                    }
                    try {
                        if (tagLen != 0) {
                            SSLCipher.checkCBCMac(signer, bb, contentType, cipheredLength, sequence);
                        } else {
                            this.authenticator.increaseSequenceNumber();
                        }
                    } catch (BadPaddingException bpe2) {
                        if (reservedBPE == null) {
                            reservedBPE = bpe2;
                        }
                    }
                    if (reservedBPE != null) {
                        throw reservedBPE;
                    }
                    return new Plaintext(contentType, ProtocolVersion.NONE.major, ProtocolVersion.NONE.minor, -1, -1L, bb.slice());
                } catch (ShortBufferException sbe) {
                    throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName(), sbe);
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public void dispose() {
                if (this.cipher != null) {
                    try {
                        this.cipher.doFinal();
                    } catch (Exception e) {
                    }
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public int estimateFragmentSize(int packetSize, int headerSize) {
                int macLen = ((Authenticator.MAC) this.authenticator).macAlg().size;
                return ((packetSize - headerSize) - macLen) - 1;
            }

            private boolean sanityCheck(int tagLen, int fragmentLen) {
                int blockSize = this.cipher.getBlockSize();
                if (fragmentLen % blockSize == 0) {
                    int minimal = tagLen + 1;
                    return fragmentLen >= (minimal >= blockSize ? minimal : blockSize);
                }
                return false;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T10BlockWriteCipherGenerator.class */
    private static final class T10BlockWriteCipherGenerator implements WriteCipherGenerator {
        private T10BlockWriteCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.WriteCipherGenerator
        public SSLWriteCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new BlockWriteCipher(authenticator, protocolVersion, algorithm, key, params, random);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T10BlockWriteCipherGenerator$BlockWriteCipher.class */
        static final class BlockWriteCipher extends SSLWriteCipher {
            private final Cipher cipher;

            BlockWriteCipher(Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = JsseJce.getCipher(algorithm);
                this.cipher.init(1, key, params, random);
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int encrypt(byte contentType, ByteBuffer bb) {
                int pos = bb.position();
                Authenticator.MAC signer = (Authenticator.MAC) this.authenticator;
                if (signer.macAlg().size != 0) {
                    SSLCipher.addMac(signer, bb, contentType);
                } else {
                    this.authenticator.increaseSequenceNumber();
                }
                int blockSize = this.cipher.getBlockSize();
                int len = SSLCipher.addPadding(bb, blockSize);
                bb.position(pos);
                if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                    SSLLogger.fine("Padded plaintext before ENCRYPTION", bb.duplicate());
                }
                ByteBuffer dup = bb.duplicate();
                try {
                    if (len != this.cipher.update(dup, bb)) {
                        throw new RuntimeException("Unexpected number of plaintext bytes");
                    }
                    if (bb.position() != dup.position()) {
                        throw new RuntimeException("Unexpected ByteBuffer position");
                    }
                    return len;
                } catch (ShortBufferException sbe) {
                    throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName(), sbe);
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public void dispose() {
                if (this.cipher != null) {
                    try {
                        this.cipher.doFinal();
                    } catch (Exception e) {
                    }
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int getExplicitNonceSize() {
                return 0;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int calculateFragmentSize(int packetLimit, int headerSize) {
                int macLen = ((Authenticator.MAC) this.authenticator).macAlg().size;
                int blockSize = this.cipher.getBlockSize();
                int fragLen = packetLimit - headerSize;
                return ((fragLen - (fragLen % blockSize)) - 1) - macLen;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int calculatePacketSize(int fragmentSize, int headerSize) {
                int macLen = ((Authenticator.MAC) this.authenticator).macAlg().size;
                int blockSize = this.cipher.getBlockSize();
                int paddedLen = fragmentSize + macLen + 1;
                if (paddedLen % blockSize != 0) {
                    int paddedLen2 = paddedLen + (blockSize - 1);
                    paddedLen = paddedLen2 - (paddedLen2 % blockSize);
                }
                return headerSize + paddedLen;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public boolean isCBCMode() {
                return true;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T11BlockReadCipherGenerator.class */
    private static final class T11BlockReadCipherGenerator implements ReadCipherGenerator {
        private T11BlockReadCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.ReadCipherGenerator
        public SSLReadCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new BlockReadCipher(authenticator, protocolVersion, sslCipher, algorithm, key, params, random);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T11BlockReadCipherGenerator$BlockReadCipher.class */
        static final class BlockReadCipher extends SSLReadCipher {
            private final Cipher cipher;

            BlockReadCipher(Authenticator authenticator, ProtocolVersion protocolVersion, SSLCipher sslCipher, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = JsseJce.getCipher(algorithm);
                this.cipher.init(2, key, params == null ? new IvParameterSpec(new byte[sslCipher.ivSize]) : params, random);
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public Plaintext decrypt(byte contentType, ByteBuffer bb, byte[] sequence) throws GeneralSecurityException {
                BadPaddingException reservedBPE = null;
                Authenticator.MAC signer = (Authenticator.MAC) this.authenticator;
                int cipheredLength = bb.remaining();
                int tagLen = signer.macAlg().size;
                if (tagLen != 0 && !sanityCheck(tagLen, bb.remaining())) {
                    reservedBPE = new BadPaddingException("ciphertext sanity check failed");
                }
                int len = bb.remaining();
                int pos = bb.position();
                ByteBuffer dup = bb.duplicate();
                try {
                    if (len != this.cipher.update(dup, bb)) {
                        throw new RuntimeException("Unexpected number of plaintext bytes");
                    }
                    if (bb.position() != dup.position()) {
                        throw new RuntimeException("Unexpected ByteBuffer position");
                    }
                    if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                        SSLLogger.fine("Padded plaintext after DECRYPTION", bb.duplicate().position(pos));
                    }
                    bb.position(pos + this.cipher.getBlockSize());
                    int pos2 = bb.position();
                    int blockSize = this.cipher.getBlockSize();
                    bb.position(pos2);
                    try {
                        SSLCipher.removePadding(bb, tagLen, blockSize, this.protocolVersion);
                    } catch (BadPaddingException bpe) {
                        if (reservedBPE == null) {
                            reservedBPE = bpe;
                        }
                    }
                    try {
                        if (tagLen != 0) {
                            SSLCipher.checkCBCMac(signer, bb, contentType, cipheredLength, sequence);
                        } else {
                            this.authenticator.increaseSequenceNumber();
                        }
                    } catch (BadPaddingException bpe2) {
                        if (reservedBPE == null) {
                            reservedBPE = bpe2;
                        }
                    }
                    if (reservedBPE != null) {
                        throw reservedBPE;
                    }
                    return new Plaintext(contentType, ProtocolVersion.NONE.major, ProtocolVersion.NONE.minor, -1, -1L, bb.slice());
                } catch (ShortBufferException sbe) {
                    throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName(), sbe);
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public void dispose() {
                if (this.cipher != null) {
                    try {
                        this.cipher.doFinal();
                    } catch (Exception e) {
                    }
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public int estimateFragmentSize(int packetSize, int headerSize) {
                int macLen = ((Authenticator.MAC) this.authenticator).macAlg().size;
                int nonceSize = this.cipher.getBlockSize();
                return (((packetSize - headerSize) - nonceSize) - macLen) - 1;
            }

            private boolean sanityCheck(int tagLen, int fragmentLen) {
                int blockSize = this.cipher.getBlockSize();
                if (fragmentLen % blockSize == 0) {
                    int minimal = tagLen + 1;
                    return fragmentLen >= (minimal >= blockSize ? minimal : blockSize) + blockSize;
                }
                return false;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T11BlockWriteCipherGenerator.class */
    private static final class T11BlockWriteCipherGenerator implements WriteCipherGenerator {
        private T11BlockWriteCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.WriteCipherGenerator
        public SSLWriteCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new BlockWriteCipher(authenticator, protocolVersion, sslCipher, algorithm, key, params, random);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T11BlockWriteCipherGenerator$BlockWriteCipher.class */
        static final class BlockWriteCipher extends SSLWriteCipher {
            private final Cipher cipher;
            private final SecureRandom random;

            BlockWriteCipher(Authenticator authenticator, ProtocolVersion protocolVersion, SSLCipher sslCipher, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = JsseJce.getCipher(algorithm);
                this.random = random;
                this.cipher.init(1, key, params == null ? new IvParameterSpec(new byte[sslCipher.ivSize]) : params, random);
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int encrypt(byte contentType, ByteBuffer bb) {
                int pos = bb.position();
                Authenticator.MAC signer = (Authenticator.MAC) this.authenticator;
                if (signer.macAlg().size != 0) {
                    SSLCipher.addMac(signer, bb, contentType);
                } else {
                    this.authenticator.increaseSequenceNumber();
                }
                byte[] nonce = new byte[this.cipher.getBlockSize()];
                this.random.nextBytes(nonce);
                int pos2 = pos - nonce.length;
                bb.position(pos2);
                bb.put(nonce);
                bb.position(pos2);
                int blockSize = this.cipher.getBlockSize();
                int len = SSLCipher.addPadding(bb, blockSize);
                bb.position(pos2);
                if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                    SSLLogger.fine("Padded plaintext before ENCRYPTION", bb.duplicate());
                }
                ByteBuffer dup = bb.duplicate();
                try {
                    if (len != this.cipher.update(dup, bb)) {
                        throw new RuntimeException("Unexpected number of plaintext bytes");
                    }
                    if (bb.position() != dup.position()) {
                        throw new RuntimeException("Unexpected ByteBuffer position");
                    }
                    return len;
                } catch (ShortBufferException sbe) {
                    throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName(), sbe);
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public void dispose() {
                if (this.cipher != null) {
                    try {
                        this.cipher.doFinal();
                    } catch (Exception e) {
                    }
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int getExplicitNonceSize() {
                return this.cipher.getBlockSize();
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int calculateFragmentSize(int packetLimit, int headerSize) {
                int macLen = ((Authenticator.MAC) this.authenticator).macAlg().size;
                int blockSize = this.cipher.getBlockSize();
                int fragLen = (packetLimit - headerSize) - blockSize;
                return ((fragLen - (fragLen % blockSize)) - 1) - macLen;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int calculatePacketSize(int fragmentSize, int headerSize) {
                int macLen = ((Authenticator.MAC) this.authenticator).macAlg().size;
                int blockSize = this.cipher.getBlockSize();
                int paddedLen = fragmentSize + macLen + 1;
                if (paddedLen % blockSize != 0) {
                    int paddedLen2 = paddedLen + (blockSize - 1);
                    paddedLen = paddedLen2 - (paddedLen2 % blockSize);
                }
                return headerSize + blockSize + paddedLen;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public boolean isCBCMode() {
                return true;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T12GcmReadCipherGenerator.class */
    private static final class T12GcmReadCipherGenerator implements ReadCipherGenerator {
        private T12GcmReadCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.ReadCipherGenerator
        public SSLReadCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new GcmReadCipher(authenticator, protocolVersion, sslCipher, algorithm, key, params, random);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T12GcmReadCipherGenerator$GcmReadCipher.class */
        static final class GcmReadCipher extends SSLReadCipher {
            private final Cipher cipher;
            private final int tagSize;
            private final Key key;
            private final byte[] fixedIv;
            private final int recordIvSize;
            private final SecureRandom random;

            GcmReadCipher(Authenticator authenticator, ProtocolVersion protocolVersion, SSLCipher sslCipher, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = JsseJce.getCipher(algorithm);
                sslCipher.getClass();
                this.tagSize = 16;
                this.key = key;
                this.fixedIv = ((IvParameterSpec) params).getIV();
                this.recordIvSize = sslCipher.ivSize - sslCipher.fixedIvSize;
                this.random = random;
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public Plaintext decrypt(byte contentType, ByteBuffer bb, byte[] sequence) throws GeneralSecurityException {
                if (bb.remaining() < this.recordIvSize + this.tagSize) {
                    throw new BadPaddingException("Insufficient buffer remaining for AEAD cipher fragment (" + bb.remaining() + "). Needs to be more than or equal to IV size (" + this.recordIvSize + ") + tag size (" + this.tagSize + ")");
                }
                byte[] iv = Arrays.copyOf(this.fixedIv, this.fixedIv.length + this.recordIvSize);
                bb.get(iv, this.fixedIv.length, this.recordIvSize);
                GCMParameterSpec spec = new GCMParameterSpec(this.tagSize * 8, iv);
                try {
                    this.cipher.init(2, this.key, spec, this.random);
                    byte[] aad = this.authenticator.acquireAuthenticationBytes(contentType, bb.remaining() - this.tagSize, sequence);
                    this.cipher.updateAAD(aad);
                    int pos = bb.position();
                    ByteBuffer dup = bb.duplicate();
                    try {
                        int len = this.cipher.doFinal(dup, bb);
                        bb.position(pos);
                        bb.limit(pos + len);
                        if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                            SSLLogger.fine("Plaintext after DECRYPTION", bb.duplicate());
                        }
                        return new Plaintext(contentType, ProtocolVersion.NONE.major, ProtocolVersion.NONE.minor, -1, -1L, bb.slice());
                    } catch (IllegalBlockSizeException ibse) {
                        throw new RuntimeException("Cipher error in AEAD mode \"" + ibse.getMessage() + " \"in JCE provider " + this.cipher.getProvider().getName());
                    } catch (ShortBufferException sbe) {
                        throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName(), sbe);
                    }
                } catch (InvalidAlgorithmParameterException | InvalidKeyException ikae) {
                    throw new RuntimeException("invalid key or spec in GCM mode", ikae);
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public void dispose() {
                if (this.cipher != null) {
                    try {
                        this.cipher.doFinal();
                    } catch (Exception e) {
                    }
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public int estimateFragmentSize(int packetSize, int headerSize) {
                return ((packetSize - headerSize) - this.recordIvSize) - this.tagSize;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T12GcmWriteCipherGenerator.class */
    private static final class T12GcmWriteCipherGenerator implements WriteCipherGenerator {
        private T12GcmWriteCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.WriteCipherGenerator
        public SSLWriteCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new GcmWriteCipher(authenticator, protocolVersion, sslCipher, algorithm, key, params, random);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T12GcmWriteCipherGenerator$GcmWriteCipher.class */
        private static final class GcmWriteCipher extends SSLWriteCipher {
            private final Cipher cipher;
            private final int tagSize;
            private final Key key;
            private final byte[] fixedIv;
            private final int recordIvSize;
            private final SecureRandom random;

            GcmWriteCipher(Authenticator authenticator, ProtocolVersion protocolVersion, SSLCipher sslCipher, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = JsseJce.getCipher(algorithm);
                sslCipher.getClass();
                this.tagSize = 16;
                this.key = key;
                this.fixedIv = ((IvParameterSpec) params).getIV();
                this.recordIvSize = sslCipher.ivSize - sslCipher.fixedIvSize;
                this.random = random;
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int encrypt(byte contentType, ByteBuffer bb) {
                byte[] nonce = this.authenticator.sequenceNumber();
                byte[] iv = Arrays.copyOf(this.fixedIv, this.fixedIv.length + nonce.length);
                System.arraycopy(nonce, 0, iv, this.fixedIv.length, nonce.length);
                GCMParameterSpec spec = new GCMParameterSpec(this.tagSize * 8, iv);
                try {
                    this.cipher.init(1, this.key, spec, this.random);
                    byte[] aad = this.authenticator.acquireAuthenticationBytes(contentType, bb.remaining(), null);
                    this.cipher.updateAAD(aad);
                    bb.position(bb.position() - nonce.length);
                    bb.put(nonce);
                    int pos = bb.position();
                    if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                        SSLLogger.fine("Plaintext before ENCRYPTION", bb.duplicate());
                    }
                    ByteBuffer dup = bb.duplicate();
                    int outputSize = this.cipher.getOutputSize(dup.remaining());
                    if (outputSize > bb.remaining()) {
                        bb.limit(pos + outputSize);
                    }
                    try {
                        int len = this.cipher.doFinal(dup, bb);
                        if (len != outputSize) {
                            throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName());
                        }
                        return len + nonce.length;
                    } catch (BadPaddingException | IllegalBlockSizeException | ShortBufferException ibse) {
                        throw new RuntimeException("Cipher error in AEAD mode in JCE provider " + this.cipher.getProvider().getName(), ibse);
                    }
                } catch (InvalidAlgorithmParameterException | InvalidKeyException ikae) {
                    throw new RuntimeException("invalid key or spec in GCM mode", ikae);
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public void dispose() {
                if (this.cipher != null) {
                    try {
                        this.cipher.doFinal();
                    } catch (Exception e) {
                    }
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int getExplicitNonceSize() {
                return this.recordIvSize;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int calculateFragmentSize(int packetLimit, int headerSize) {
                return ((packetLimit - headerSize) - this.recordIvSize) - this.tagSize;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int calculatePacketSize(int fragmentSize, int headerSize) {
                return fragmentSize + headerSize + this.recordIvSize + this.tagSize;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T13GcmReadCipherGenerator.class */
    private static final class T13GcmReadCipherGenerator implements ReadCipherGenerator {
        private T13GcmReadCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.ReadCipherGenerator
        public SSLReadCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new GcmReadCipher(authenticator, protocolVersion, sslCipher, algorithm, key, params, random);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T13GcmReadCipherGenerator$GcmReadCipher.class */
        static final class GcmReadCipher extends SSLReadCipher {
            private final Cipher cipher;
            private final int tagSize;
            private final Key key;

            /* renamed from: iv */
            private final byte[] f984iv;
            private final SecureRandom random;

            GcmReadCipher(Authenticator authenticator, ProtocolVersion protocolVersion, SSLCipher sslCipher, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = JsseJce.getCipher(algorithm);
                sslCipher.getClass();
                this.tagSize = 16;
                this.key = key;
                this.f984iv = ((IvParameterSpec) params).getIV();
                this.random = random;
                this.keyLimitCountdown = ((Long) SSLCipher.cipherLimits.getOrDefault(algorithm.toUpperCase() + ":" + SSLCipher.tag[0], 0L)).longValue();
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.fine("KeyLimit read side: algorithm = " + algorithm.toUpperCase() + ":" + SSLCipher.tag[0] + "\ncountdown value = " + this.keyLimitCountdown, new Object[0]);
                }
                if (this.keyLimitCountdown > 0) {
                    this.keyLimitEnabled = true;
                }
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public Plaintext decrypt(byte contentType, ByteBuffer bb, byte[] sequence) throws GeneralSecurityException {
                if (contentType == ContentType.CHANGE_CIPHER_SPEC.f965id) {
                    return new Plaintext(contentType, ProtocolVersion.NONE.major, ProtocolVersion.NONE.minor, -1, -1L, bb.slice());
                }
                if (bb.remaining() <= this.tagSize) {
                    throw new BadPaddingException("Insufficient buffer remaining for AEAD cipher fragment (" + bb.remaining() + "). Needs to be more than tag size (" + this.tagSize + ")");
                }
                byte[] sn = sequence;
                if (sn == null) {
                    sn = this.authenticator.sequenceNumber();
                }
                byte[] nonce = (byte[]) this.f984iv.clone();
                int offset = nonce.length - sn.length;
                for (int i = 0; i < sn.length; i++) {
                    int i2 = offset + i;
                    nonce[i2] = (byte) (nonce[i2] ^ sn[i]);
                }
                GCMParameterSpec spec = new GCMParameterSpec(this.tagSize * 8, nonce);
                try {
                    this.cipher.init(2, this.key, spec, this.random);
                    byte[] aad = this.authenticator.acquireAuthenticationBytes(contentType, bb.remaining(), sn);
                    this.cipher.updateAAD(aad);
                    int pos = bb.position();
                    ByteBuffer dup = bb.duplicate();
                    try {
                        int len = this.cipher.doFinal(dup, bb);
                        bb.position(pos);
                        bb.limit(pos + len);
                        int i3 = bb.limit() - 1;
                        while (i3 > 0 && bb.get(i3) == 0) {
                            i3--;
                        }
                        if (i3 < pos + 1) {
                            throw new BadPaddingException("Incorrect inner plaintext: no content type");
                        }
                        byte contentType2 = bb.get(i3);
                        bb.limit(i3);
                        if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                            SSLLogger.fine("Plaintext after DECRYPTION", bb.duplicate());
                        }
                        if (this.keyLimitEnabled) {
                            this.keyLimitCountdown -= len;
                        }
                        return new Plaintext(contentType2, ProtocolVersion.NONE.major, ProtocolVersion.NONE.minor, -1, -1L, bb.slice());
                    } catch (IllegalBlockSizeException ibse) {
                        throw new RuntimeException("Cipher error in AEAD mode \"" + ibse.getMessage() + " \"in JCE provider " + this.cipher.getProvider().getName());
                    } catch (ShortBufferException sbe) {
                        throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName(), sbe);
                    }
                } catch (InvalidAlgorithmParameterException | InvalidKeyException ikae) {
                    throw new RuntimeException("invalid key or spec in GCM mode", ikae);
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public void dispose() {
                if (this.cipher != null) {
                    try {
                        this.cipher.doFinal();
                    } catch (Exception e) {
                    }
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public int estimateFragmentSize(int packetSize, int headerSize) {
                return (packetSize - headerSize) - this.tagSize;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T13GcmWriteCipherGenerator.class */
    private static final class T13GcmWriteCipherGenerator implements WriteCipherGenerator {
        private T13GcmWriteCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.WriteCipherGenerator
        public SSLWriteCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new GcmWriteCipher(authenticator, protocolVersion, sslCipher, algorithm, key, params, random);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T13GcmWriteCipherGenerator$GcmWriteCipher.class */
        private static final class GcmWriteCipher extends SSLWriteCipher {
            private final Cipher cipher;
            private final int tagSize;
            private final Key key;

            /* renamed from: iv */
            private final byte[] f985iv;
            private final SecureRandom random;

            GcmWriteCipher(Authenticator authenticator, ProtocolVersion protocolVersion, SSLCipher sslCipher, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = JsseJce.getCipher(algorithm);
                sslCipher.getClass();
                this.tagSize = 16;
                this.key = key;
                this.f985iv = ((IvParameterSpec) params).getIV();
                this.random = random;
                this.keyLimitCountdown = ((Long) SSLCipher.cipherLimits.getOrDefault(algorithm.toUpperCase() + ":" + SSLCipher.tag[0], 0L)).longValue();
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.fine("KeyLimit write side: algorithm = " + algorithm.toUpperCase() + ":" + SSLCipher.tag[0] + "\ncountdown value = " + this.keyLimitCountdown, new Object[0]);
                }
                if (this.keyLimitCountdown > 0) {
                    this.keyLimitEnabled = true;
                }
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int encrypt(byte contentType, ByteBuffer bb) {
                byte[] sn = this.authenticator.sequenceNumber();
                byte[] nonce = (byte[]) this.f985iv.clone();
                int offset = nonce.length - sn.length;
                for (int i = 0; i < sn.length; i++) {
                    int i2 = offset + i;
                    nonce[i2] = (byte) (nonce[i2] ^ sn[i]);
                }
                GCMParameterSpec spec = new GCMParameterSpec(this.tagSize * 8, nonce);
                try {
                    this.cipher.init(1, this.key, spec, this.random);
                    int outputSize = this.cipher.getOutputSize(bb.remaining());
                    byte[] aad = this.authenticator.acquireAuthenticationBytes(contentType, outputSize, sn);
                    this.cipher.updateAAD(aad);
                    int pos = bb.position();
                    if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                        SSLLogger.fine("Plaintext before ENCRYPTION", bb.duplicate());
                    }
                    ByteBuffer dup = bb.duplicate();
                    if (outputSize > bb.remaining()) {
                        bb.limit(pos + outputSize);
                    }
                    try {
                        int len = this.cipher.doFinal(dup, bb);
                        if (len != outputSize) {
                            throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName());
                        }
                        if (this.keyLimitEnabled) {
                            this.keyLimitCountdown -= len;
                        }
                        return len;
                    } catch (BadPaddingException | IllegalBlockSizeException | ShortBufferException ibse) {
                        throw new RuntimeException("Cipher error in AEAD mode in JCE provider " + this.cipher.getProvider().getName(), ibse);
                    }
                } catch (InvalidAlgorithmParameterException | InvalidKeyException ikae) {
                    throw new RuntimeException("invalid key or spec in GCM mode", ikae);
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public void dispose() {
                if (this.cipher != null) {
                    try {
                        this.cipher.doFinal();
                    } catch (Exception e) {
                    }
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int getExplicitNonceSize() {
                return 0;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int calculateFragmentSize(int packetLimit, int headerSize) {
                return (packetLimit - headerSize) - this.tagSize;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int calculatePacketSize(int fragmentSize, int headerSize) {
                return fragmentSize + headerSize + this.tagSize;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T12CC20P1305ReadCipherGenerator.class */
    private static final class T12CC20P1305ReadCipherGenerator implements ReadCipherGenerator {
        private T12CC20P1305ReadCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.ReadCipherGenerator
        public SSLReadCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new CC20P1305ReadCipher(authenticator, protocolVersion, sslCipher, algorithm, key, params, random);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T12CC20P1305ReadCipherGenerator$CC20P1305ReadCipher.class */
        static final class CC20P1305ReadCipher extends SSLReadCipher {
            private final Cipher cipher;
            private final int tagSize;
            private final Key key;

            /* renamed from: iv */
            private final byte[] f980iv;
            private final SecureRandom random;

            CC20P1305ReadCipher(Authenticator authenticator, ProtocolVersion protocolVersion, SSLCipher sslCipher, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = JsseJce.getCipher(algorithm);
                sslCipher.getClass();
                this.tagSize = 16;
                this.key = key;
                this.f980iv = ((IvParameterSpec) params).getIV();
                this.random = random;
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public Plaintext decrypt(byte contentType, ByteBuffer bb, byte[] sequence) throws GeneralSecurityException {
                if (bb.remaining() <= this.tagSize) {
                    throw new BadPaddingException("Insufficient buffer remaining for AEAD cipher fragment (" + bb.remaining() + "). Needs to be more than tag size (" + this.tagSize + ")");
                }
                byte[] sn = sequence;
                if (sn == null) {
                    sn = this.authenticator.sequenceNumber();
                }
                byte[] nonce = new byte[this.f980iv.length];
                System.arraycopy(sn, 0, nonce, nonce.length - sn.length, sn.length);
                for (int i = 0; i < nonce.length; i++) {
                    int i2 = i;
                    nonce[i2] = (byte) (nonce[i2] ^ this.f980iv[i]);
                }
                AlgorithmParameterSpec spec = new IvParameterSpec(nonce);
                try {
                    this.cipher.init(2, this.key, spec, this.random);
                    byte[] aad = this.authenticator.acquireAuthenticationBytes(contentType, bb.remaining() - this.tagSize, sequence);
                    this.cipher.updateAAD(aad);
                    bb.remaining();
                    int pos = bb.position();
                    ByteBuffer dup = bb.duplicate();
                    try {
                        int len = this.cipher.doFinal(dup, bb);
                        bb.position(pos);
                        bb.limit(pos + len);
                        if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                            SSLLogger.fine("Plaintext after DECRYPTION", bb.duplicate());
                        }
                        return new Plaintext(contentType, ProtocolVersion.NONE.major, ProtocolVersion.NONE.minor, -1, -1L, bb.slice());
                    } catch (IllegalBlockSizeException ibse) {
                        throw new RuntimeException("Cipher error in AEAD mode \"" + ibse.getMessage() + " \"in JCE provider " + this.cipher.getProvider().getName());
                    } catch (ShortBufferException sbe) {
                        throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName(), sbe);
                    }
                } catch (InvalidAlgorithmParameterException | InvalidKeyException ikae) {
                    throw new RuntimeException("invalid key or spec in AEAD mode", ikae);
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public void dispose() {
                if (this.cipher != null) {
                    try {
                        this.cipher.doFinal();
                    } catch (Exception e) {
                    }
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public int estimateFragmentSize(int packetSize, int headerSize) {
                return (packetSize - headerSize) - this.tagSize;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T12CC20P1305WriteCipherGenerator.class */
    private static final class T12CC20P1305WriteCipherGenerator implements WriteCipherGenerator {
        private T12CC20P1305WriteCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.WriteCipherGenerator
        public SSLWriteCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new CC20P1305WriteCipher(authenticator, protocolVersion, sslCipher, algorithm, key, params, random);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T12CC20P1305WriteCipherGenerator$CC20P1305WriteCipher.class */
        private static final class CC20P1305WriteCipher extends SSLWriteCipher {
            private final Cipher cipher;
            private final int tagSize;
            private final Key key;

            /* renamed from: iv */
            private final byte[] f981iv;
            private final SecureRandom random;

            CC20P1305WriteCipher(Authenticator authenticator, ProtocolVersion protocolVersion, SSLCipher sslCipher, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = JsseJce.getCipher(algorithm);
                sslCipher.getClass();
                this.tagSize = 16;
                this.key = key;
                this.f981iv = ((IvParameterSpec) params).getIV();
                this.random = random;
                this.keyLimitCountdown = ((Long) SSLCipher.cipherLimits.getOrDefault(algorithm.toUpperCase() + ":" + SSLCipher.tag[0], 0L)).longValue();
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.fine("algorithm = " + algorithm.toUpperCase() + ":" + SSLCipher.tag[0] + "\ncountdown value = " + this.keyLimitCountdown, new Object[0]);
                }
                if (this.keyLimitCountdown > 0) {
                    this.keyLimitEnabled = true;
                }
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int encrypt(byte contentType, ByteBuffer bb) {
                byte[] sn = this.authenticator.sequenceNumber();
                byte[] nonce = new byte[this.f981iv.length];
                System.arraycopy(sn, 0, nonce, nonce.length - sn.length, sn.length);
                for (int i = 0; i < nonce.length; i++) {
                    int i2 = i;
                    nonce[i2] = (byte) (nonce[i2] ^ this.f981iv[i]);
                }
                AlgorithmParameterSpec spec = new IvParameterSpec(nonce);
                try {
                    this.cipher.init(1, this.key, spec, this.random);
                    byte[] aad = this.authenticator.acquireAuthenticationBytes(contentType, bb.remaining(), null);
                    this.cipher.updateAAD(aad);
                    bb.remaining();
                    int pos = bb.position();
                    if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                        SSLLogger.fine("Plaintext before ENCRYPTION", bb.duplicate());
                    }
                    ByteBuffer dup = bb.duplicate();
                    int outputSize = this.cipher.getOutputSize(dup.remaining());
                    if (outputSize > bb.remaining()) {
                        bb.limit(pos + outputSize);
                    }
                    try {
                        int len = this.cipher.doFinal(dup, bb);
                        if (len != outputSize) {
                            throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName());
                        }
                        return len;
                    } catch (BadPaddingException | IllegalBlockSizeException | ShortBufferException ibse) {
                        throw new RuntimeException("Cipher error in AEAD mode in JCE provider " + this.cipher.getProvider().getName(), ibse);
                    }
                } catch (InvalidAlgorithmParameterException | InvalidKeyException ikae) {
                    throw new RuntimeException("invalid key or spec in AEAD mode", ikae);
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public void dispose() {
                if (this.cipher != null) {
                    try {
                        this.cipher.doFinal();
                    } catch (Exception e) {
                    }
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int getExplicitNonceSize() {
                return 0;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int calculateFragmentSize(int packetLimit, int headerSize) {
                return (packetLimit - headerSize) - this.tagSize;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int calculatePacketSize(int fragmentSize, int headerSize) {
                return fragmentSize + headerSize + this.tagSize;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T13CC20P1305ReadCipherGenerator.class */
    private static final class T13CC20P1305ReadCipherGenerator implements ReadCipherGenerator {
        private T13CC20P1305ReadCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.ReadCipherGenerator
        public SSLReadCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new CC20P1305ReadCipher(authenticator, protocolVersion, sslCipher, algorithm, key, params, random);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T13CC20P1305ReadCipherGenerator$CC20P1305ReadCipher.class */
        static final class CC20P1305ReadCipher extends SSLReadCipher {
            private final Cipher cipher;
            private final int tagSize;
            private final Key key;

            /* renamed from: iv */
            private final byte[] f982iv;
            private final SecureRandom random;

            CC20P1305ReadCipher(Authenticator authenticator, ProtocolVersion protocolVersion, SSLCipher sslCipher, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = JsseJce.getCipher(algorithm);
                sslCipher.getClass();
                this.tagSize = 16;
                this.key = key;
                this.f982iv = ((IvParameterSpec) params).getIV();
                this.random = random;
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public Plaintext decrypt(byte contentType, ByteBuffer bb, byte[] sequence) throws GeneralSecurityException {
                if (contentType == ContentType.CHANGE_CIPHER_SPEC.f965id) {
                    return new Plaintext(contentType, ProtocolVersion.NONE.major, ProtocolVersion.NONE.minor, -1, -1L, bb.slice());
                }
                if (bb.remaining() <= this.tagSize) {
                    throw new BadPaddingException("Insufficient buffer remaining for AEAD cipher fragment (" + bb.remaining() + "). Needs to be more than tag size (" + this.tagSize + ")");
                }
                byte[] sn = sequence;
                if (sn == null) {
                    sn = this.authenticator.sequenceNumber();
                }
                byte[] nonce = new byte[this.f982iv.length];
                System.arraycopy(sn, 0, nonce, nonce.length - sn.length, sn.length);
                for (int i = 0; i < nonce.length; i++) {
                    int i2 = i;
                    nonce[i2] = (byte) (nonce[i2] ^ this.f982iv[i]);
                }
                AlgorithmParameterSpec spec = new IvParameterSpec(nonce);
                try {
                    this.cipher.init(2, this.key, spec, this.random);
                    byte[] aad = this.authenticator.acquireAuthenticationBytes(contentType, bb.remaining(), sn);
                    this.cipher.updateAAD(aad);
                    bb.remaining();
                    int pos = bb.position();
                    ByteBuffer dup = bb.duplicate();
                    try {
                        int len = this.cipher.doFinal(dup, bb);
                        bb.position(pos);
                        bb.limit(pos + len);
                        int i3 = bb.limit() - 1;
                        while (i3 > 0 && bb.get(i3) == 0) {
                            i3--;
                        }
                        if (i3 < pos + 1) {
                            throw new BadPaddingException("Incorrect inner plaintext: no content type");
                        }
                        byte contentType2 = bb.get(i3);
                        bb.limit(i3);
                        if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                            SSLLogger.fine("Plaintext after DECRYPTION", bb.duplicate());
                        }
                        return new Plaintext(contentType2, ProtocolVersion.NONE.major, ProtocolVersion.NONE.minor, -1, -1L, bb.slice());
                    } catch (IllegalBlockSizeException ibse) {
                        throw new RuntimeException("Cipher error in AEAD mode \"" + ibse.getMessage() + " \"in JCE provider " + this.cipher.getProvider().getName());
                    } catch (ShortBufferException sbe) {
                        throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName(), sbe);
                    }
                } catch (InvalidAlgorithmParameterException | InvalidKeyException ikae) {
                    throw new RuntimeException("invalid key or spec in AEAD mode", ikae);
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public void dispose() {
                if (this.cipher != null) {
                    try {
                        this.cipher.doFinal();
                    } catch (Exception e) {
                    }
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLReadCipher
            public int estimateFragmentSize(int packetSize, int headerSize) {
                return (packetSize - headerSize) - this.tagSize;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T13CC20P1305WriteCipherGenerator.class */
    private static final class T13CC20P1305WriteCipherGenerator implements WriteCipherGenerator {
        private T13CC20P1305WriteCipherGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLCipher.WriteCipherGenerator
        public SSLWriteCipher createCipher(SSLCipher sslCipher, Authenticator authenticator, ProtocolVersion protocolVersion, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
            return new CC20P1305WriteCipher(authenticator, protocolVersion, sslCipher, algorithm, key, params, random);
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLCipher$T13CC20P1305WriteCipherGenerator$CC20P1305WriteCipher.class */
        private static final class CC20P1305WriteCipher extends SSLWriteCipher {
            private final Cipher cipher;
            private final int tagSize;
            private final Key key;

            /* renamed from: iv */
            private final byte[] f983iv;
            private final SecureRandom random;

            CC20P1305WriteCipher(Authenticator authenticator, ProtocolVersion protocolVersion, SSLCipher sslCipher, String algorithm, Key key, AlgorithmParameterSpec params, SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = JsseJce.getCipher(algorithm);
                sslCipher.getClass();
                this.tagSize = 16;
                this.key = key;
                this.f983iv = ((IvParameterSpec) params).getIV();
                this.random = random;
                this.keyLimitCountdown = ((Long) SSLCipher.cipherLimits.getOrDefault(algorithm.toUpperCase() + ":" + SSLCipher.tag[0], 0L)).longValue();
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.fine("algorithm = " + algorithm.toUpperCase() + ":" + SSLCipher.tag[0] + "\ncountdown value = " + this.keyLimitCountdown, new Object[0]);
                }
                if (this.keyLimitCountdown > 0) {
                    this.keyLimitEnabled = true;
                }
            }

            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int encrypt(byte contentType, ByteBuffer bb) {
                byte[] sn = this.authenticator.sequenceNumber();
                byte[] nonce = new byte[this.f983iv.length];
                System.arraycopy(sn, 0, nonce, nonce.length - sn.length, sn.length);
                for (int i = 0; i < nonce.length; i++) {
                    int i2 = i;
                    nonce[i2] = (byte) (nonce[i2] ^ this.f983iv[i]);
                }
                AlgorithmParameterSpec spec = new IvParameterSpec(nonce);
                try {
                    this.cipher.init(1, this.key, spec, this.random);
                    int outputSize = this.cipher.getOutputSize(bb.remaining());
                    byte[] aad = this.authenticator.acquireAuthenticationBytes(contentType, outputSize, sn);
                    this.cipher.updateAAD(aad);
                    bb.remaining();
                    int pos = bb.position();
                    if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                        SSLLogger.fine("Plaintext before ENCRYPTION", bb.duplicate());
                    }
                    ByteBuffer dup = bb.duplicate();
                    if (outputSize > bb.remaining()) {
                        bb.limit(pos + outputSize);
                    }
                    try {
                        int len = this.cipher.doFinal(dup, bb);
                        if (len != outputSize) {
                            throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName());
                        }
                        if (this.keyLimitEnabled) {
                            this.keyLimitCountdown -= len;
                        }
                        return len;
                    } catch (BadPaddingException | IllegalBlockSizeException | ShortBufferException ibse) {
                        throw new RuntimeException("Cipher error in AEAD mode in JCE provider " + this.cipher.getProvider().getName(), ibse);
                    }
                } catch (InvalidAlgorithmParameterException | InvalidKeyException ikae) {
                    throw new RuntimeException("invalid key or spec in AEAD mode", ikae);
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public void dispose() {
                if (this.cipher != null) {
                    try {
                        this.cipher.doFinal();
                    } catch (Exception e) {
                    }
                }
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int getExplicitNonceSize() {
                return 0;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int calculateFragmentSize(int packetLimit, int headerSize) {
                return (packetLimit - headerSize) - this.tagSize;
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            @Override // org.openjsse.sun.security.ssl.SSLCipher.SSLWriteCipher
            public int calculatePacketSize(int fragmentSize, int headerSize) {
                return fragmentSize + headerSize + this.tagSize;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void addMac(Authenticator.MAC signer, ByteBuffer destination, byte contentType) {
        if (signer.macAlg().size != 0) {
            int dstContent = destination.position();
            byte[] hash = signer.compute(contentType, destination, false);
            destination.limit(destination.limit() + hash.length);
            destination.put(hash);
            destination.position(dstContent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void checkStreamMac(Authenticator.MAC signer, ByteBuffer bb, byte contentType, byte[] sequence) throws BadPaddingException {
        int tagLen = signer.macAlg().size;
        if (tagLen != 0) {
            int contentLen = bb.remaining() - tagLen;
            if (contentLen < 0) {
                throw new BadPaddingException("bad record");
            }
            if (checkMacTags(contentType, bb, signer, sequence, false)) {
                throw new BadPaddingException("bad record MAC");
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void checkCBCMac(Authenticator.MAC signer, ByteBuffer bb, byte contentType, int cipheredLength, byte[] sequence) throws BadPaddingException {
        BadPaddingException reservedBPE = null;
        int tagLen = signer.macAlg().size;
        int pos = bb.position();
        if (tagLen != 0) {
            int contentLen = bb.remaining() - tagLen;
            if (contentLen < 0) {
                reservedBPE = new BadPaddingException("bad record");
                contentLen = cipheredLength - tagLen;
                bb.limit(pos + cipheredLength);
            }
            if (checkMacTags(contentType, bb, signer, sequence, false) && reservedBPE == null) {
                reservedBPE = new BadPaddingException("bad record MAC");
            }
            int remainingLen = calculateRemainingLen(signer, cipheredLength, contentLen);
            ByteBuffer temporary = ByteBuffer.allocate(remainingLen + signer.macAlg().size);
            checkMacTags(contentType, temporary, signer, sequence, true);
        }
        if (reservedBPE != null) {
            throw reservedBPE;
        }
    }

    private static boolean checkMacTags(byte contentType, ByteBuffer bb, Authenticator.MAC signer, byte[] sequence, boolean isSimulated) {
        int tagLen = signer.macAlg().size;
        int position = bb.position();
        int lim = bb.limit();
        int macOffset = lim - tagLen;
        bb.limit(macOffset);
        byte[] hash = signer.compute(contentType, bb, sequence, isSimulated);
        if (hash == null || tagLen != hash.length) {
            throw new RuntimeException("Internal MAC error");
        }
        bb.position(macOffset);
        bb.limit(lim);
        try {
            int[] results = compareMacTags(bb, hash);
            return results[0] != 0;
        } finally {
            bb.position(position);
            bb.limit(macOffset);
        }
    }

    private static int[] compareMacTags(ByteBuffer bb, byte[] tag2) {
        int[] results = {0, 0};
        for (byte t : tag2) {
            if (bb.get() != t) {
                results[0] = results[0] + 1;
            } else {
                results[1] = results[1] + 1;
            }
        }
        return results;
    }

    private static int calculateRemainingLen(Authenticator.MAC signer, int fullLen, int usedLen) {
        int blockLen = signer.macAlg().hashBlockSize;
        int minimalPaddingLen = signer.macAlg().minimalPaddingSize;
        return 1 + (((int) (Math.ceil((fullLen + (13 - (blockLen - minimalPaddingLen))) / (1.0d * blockLen)) - Math.ceil((usedLen + (13 - (blockLen - minimalPaddingLen))) / (1.0d * blockLen)))) * blockLen);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int addPadding(ByteBuffer bb, int blockSize) {
        int len = bb.remaining();
        int offset = bb.position();
        int newlen = len + 1;
        if (newlen % blockSize != 0) {
            int newlen2 = newlen + (blockSize - 1);
            newlen = newlen2 - (newlen2 % blockSize);
        }
        int pad = (byte) (newlen - len);
        bb.limit(newlen + offset);
        int offset2 = offset + len;
        for (int i = 0; i < pad; i++) {
            int i2 = offset2;
            offset2++;
            bb.put(i2, (byte) (pad - 1));
        }
        bb.position(offset2);
        bb.limit(offset2);
        return newlen;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int removePadding(ByteBuffer bb, int tagLen, int blockSize, ProtocolVersion protocolVersion) throws BadPaddingException {
        int len = bb.remaining();
        int offset = bb.position();
        int padOffset = (offset + len) - 1;
        int padLen = bb.get(padOffset) & 255;
        int newLen = len - (padLen + 1);
        if (newLen - tagLen < 0) {
            checkPadding(bb.duplicate(), (byte) (padLen & GF2Field.MASK));
            throw new BadPaddingException("Invalid Padding length: " + padLen);
        }
        int[] results = checkPadding((ByteBuffer) bb.duplicate().position(offset + newLen), (byte) (padLen & GF2Field.MASK));
        if (protocolVersion.useTLS10PlusSpec()) {
            if (results[0] != 0) {
                throw new BadPaddingException("Invalid TLS padding data");
            }
        } else if (padLen > blockSize) {
            throw new BadPaddingException("Padding length (" + padLen + ") of SSLv3 message should not be bigger than the block size (" + blockSize + ")");
        }
        bb.limit(offset + newLen);
        return newLen;
    }

    private static int[] checkPadding(ByteBuffer bb, byte pad) {
        if (!bb.hasRemaining()) {
            throw new RuntimeException("hasRemaining() must be positive");
        }
        int[] results = {0, 0};
        bb.mark();
        int i = 0;
        while (i <= 256) {
            while (bb.hasRemaining() && i <= 256) {
                if (bb.get() != pad) {
                    results[0] = results[0] + 1;
                } else {
                    results[1] = results[1] + 1;
                }
                i++;
            }
            bb.reset();
        }
        return results;
    }
}