package org.openjsse.sun.security.ssl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedList;
import javax.crypto.SecretKey;
import org.openjsse.sun.security.util.MessageDigestSpi2;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HandshakeHash.class */
public final class HandshakeHash {
    private TranscriptHash transcriptHash = new CacheOnlyHash();
    private LinkedList<byte[]> reserves = new LinkedList<>();
    private boolean hasBeenUsed = false;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HandshakeHash$TranscriptHash.class */
    public interface TranscriptHash {
        void update(byte[] bArr, int i, int i2);

        byte[] digest();

        byte[] archived();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void determine(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
        if (!(this.transcriptHash instanceof CacheOnlyHash)) {
            throw new IllegalStateException("Not expected instance of transcript hash");
        }
        CacheOnlyHash coh = (CacheOnlyHash) this.transcriptHash;
        if (protocolVersion.useTLS13PlusSpec()) {
            this.transcriptHash = new T13HandshakeHash(cipherSuite);
        } else if (protocolVersion.useTLS12PlusSpec()) {
            this.transcriptHash = new T12HandshakeHash(cipherSuite);
        } else if (protocolVersion.useTLS10PlusSpec()) {
            this.transcriptHash = new T10HandshakeHash(cipherSuite);
        } else {
            this.transcriptHash = new S30HandshakeHash(cipherSuite);
        }
        byte[] reserved = coh.baos.toByteArray();
        if (reserved.length != 0) {
            this.transcriptHash.update(reserved, 0, reserved.length);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public HandshakeHash copy() {
        if (this.transcriptHash instanceof CacheOnlyHash) {
            HandshakeHash result = new HandshakeHash();
            result.transcriptHash = ((CacheOnlyHash) this.transcriptHash).copy();
            result.reserves = new LinkedList<>(this.reserves);
            result.hasBeenUsed = this.hasBeenUsed;
            return result;
        }
        throw new IllegalStateException("Hash does not support copying");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void receive(byte[] input) {
        this.reserves.add(Arrays.copyOf(input, input.length));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void receive(ByteBuffer input, int length) {
        if (input.hasArray()) {
            int from = input.position() + input.arrayOffset();
            int to = from + length;
            this.reserves.add(Arrays.copyOfRange(input.array(), from, to));
            return;
        }
        int inPos = input.position();
        byte[] holder = new byte[length];
        input.get(holder);
        input.position(inPos);
        this.reserves.add(Arrays.copyOf(holder, holder.length));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void receive(ByteBuffer input) {
        receive(input, input.remaining());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void push(byte[] input) {
        this.reserves.push(Arrays.copyOf(input, input.length));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] removeLastReceived() {
        return this.reserves.removeLast();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void deliver(byte[] input) {
        update();
        this.transcriptHash.update(input, 0, input.length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void deliver(byte[] input, int offset, int length) {
        update();
        this.transcriptHash.update(input, offset, length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void deliver(ByteBuffer input) {
        update();
        if (input.hasArray()) {
            this.transcriptHash.update(input.array(), input.position() + input.arrayOffset(), input.remaining());
            return;
        }
        int inPos = input.position();
        byte[] holder = new byte[input.remaining()];
        input.get(holder);
        input.position(inPos);
        this.transcriptHash.update(holder, 0, holder.length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void utilize() {
        if (!this.hasBeenUsed && this.reserves.size() != 0) {
            byte[] holder = this.reserves.remove();
            this.transcriptHash.update(holder, 0, holder.length);
            this.hasBeenUsed = true;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void consume() {
        if (this.hasBeenUsed) {
            this.hasBeenUsed = false;
        } else if (this.reserves.size() != 0) {
            byte[] holder = this.reserves.remove();
            this.transcriptHash.update(holder, 0, holder.length);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void update() {
        while (this.reserves.size() != 0) {
            byte[] holder = this.reserves.remove();
            this.transcriptHash.update(holder, 0, holder.length);
        }
        this.hasBeenUsed = false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] digest() {
        return this.transcriptHash.digest();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void finish() {
        this.transcriptHash = new CacheOnlyHash();
        this.reserves = new LinkedList<>();
        this.hasBeenUsed = false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] archived() {
        return this.transcriptHash.archived();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] digest(String algorithm) {
        T10HandshakeHash hh = (T10HandshakeHash) this.transcriptHash;
        return hh.digest(algorithm);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] digest(String algorithm, SecretKey masterSecret) {
        S30HandshakeHash hh = (S30HandshakeHash) this.transcriptHash;
        return hh.digest(algorithm, masterSecret);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] digest(boolean useClientLabel, SecretKey masterSecret) {
        S30HandshakeHash hh = (S30HandshakeHash) this.transcriptHash;
        return hh.digest(useClientLabel, masterSecret);
    }

    public boolean isHashable(byte handshakeType) {
        return (handshakeType == SSLHandshake.HELLO_REQUEST.f987id || handshakeType == SSLHandshake.HELLO_VERIFY_REQUEST.f987id) ? false : true;
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HandshakeHash$CacheOnlyHash.class */
    private static final class CacheOnlyHash implements TranscriptHash {
        private final ByteArrayOutputStream baos = new ByteArrayOutputStream();

        CacheOnlyHash() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public void update(byte[] input, int offset, int length) {
            this.baos.write(input, offset, length);
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public byte[] digest() {
            throw new IllegalStateException("Not expected call to handshake hash digest");
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public byte[] archived() {
            return this.baos.toByteArray();
        }

        CacheOnlyHash copy() {
            CacheOnlyHash result = new CacheOnlyHash();
            try {
                this.baos.writeTo(result.baos);
                return result;
            } catch (IOException e) {
                throw new RuntimeException("unable to to clone hash state");
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HandshakeHash$S30HandshakeHash.class */
    static final class S30HandshakeHash implements TranscriptHash {
        static final byte[] MD5_pad1 = genPad(54, 48);
        static final byte[] MD5_pad2 = genPad(92, 48);
        static final byte[] SHA_pad1 = genPad(54, 40);
        static final byte[] SHA_pad2 = genPad(92, 40);
        private static final byte[] SSL_CLIENT = {67, 76, 78, 84};
        private static final byte[] SSL_SERVER = {83, 82, 86, 82};
        private final MessageDigest mdMD5 = JsseJce.getMessageDigest("MD5");
        private final MessageDigest mdSHA = JsseJce.getMessageDigest("SHA");
        private final TranscriptHash md5;
        private final TranscriptHash sha;
        private final ByteArrayOutputStream baos;

        S30HandshakeHash(CipherSuite cipherSuite) {
            boolean hasArchived = false;
            if (this.mdMD5 instanceof Cloneable) {
                this.md5 = new CloneableHash(this.mdMD5);
            } else {
                hasArchived = true;
                this.md5 = new NonCloneableHash(this.mdMD5);
            }
            if (this.mdSHA instanceof Cloneable) {
                this.sha = new CloneableHash(this.mdSHA);
            } else {
                hasArchived = true;
                this.sha = new NonCloneableHash(this.mdSHA);
            }
            if (hasArchived) {
                this.baos = null;
            } else {
                this.baos = new ByteArrayOutputStream();
            }
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public void update(byte[] input, int offset, int length) {
            this.md5.update(input, offset, length);
            this.sha.update(input, offset, length);
            if (this.baos != null) {
                this.baos.write(input, offset, length);
            }
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public byte[] digest() {
            byte[] digest = new byte[36];
            System.arraycopy(this.md5.digest(), 0, digest, 0, 16);
            System.arraycopy(this.sha.digest(), 0, digest, 16, 20);
            return digest;
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public byte[] archived() {
            if (this.baos != null) {
                return this.baos.toByteArray();
            }
            if (this.md5 instanceof NonCloneableHash) {
                return this.md5.archived();
            }
            return this.sha.archived();
        }

        byte[] digest(boolean useClientLabel, SecretKey masterSecret) {
            MessageDigest md5Clone = cloneMd5();
            MessageDigest shaClone = cloneSha();
            if (useClientLabel) {
                md5Clone.update(SSL_CLIENT);
                shaClone.update(SSL_CLIENT);
            } else {
                md5Clone.update(SSL_SERVER);
                shaClone.update(SSL_SERVER);
            }
            updateDigest(md5Clone, MD5_pad1, MD5_pad2, masterSecret);
            updateDigest(shaClone, SHA_pad1, SHA_pad2, masterSecret);
            byte[] digest = new byte[36];
            System.arraycopy(md5Clone.digest(), 0, digest, 0, 16);
            System.arraycopy(shaClone.digest(), 0, digest, 16, 20);
            return digest;
        }

        byte[] digest(String algorithm, SecretKey masterSecret) {
            if ("RSA".equalsIgnoreCase(algorithm)) {
                MessageDigest md5Clone = cloneMd5();
                MessageDigest shaClone = cloneSha();
                updateDigest(md5Clone, MD5_pad1, MD5_pad2, masterSecret);
                updateDigest(shaClone, SHA_pad1, SHA_pad2, masterSecret);
                byte[] digest = new byte[36];
                System.arraycopy(md5Clone.digest(), 0, digest, 0, 16);
                System.arraycopy(shaClone.digest(), 0, digest, 16, 20);
                return digest;
            }
            MessageDigest shaClone2 = cloneSha();
            updateDigest(shaClone2, SHA_pad1, SHA_pad2, masterSecret);
            return shaClone2.digest();
        }

        private static byte[] genPad(int b, int count) {
            byte[] padding = new byte[count];
            Arrays.fill(padding, (byte) b);
            return padding;
        }

        private MessageDigest cloneMd5() {
            MessageDigest md5Clone;
            if (this.mdMD5 instanceof Cloneable) {
                try {
                    md5Clone = (MessageDigest) this.mdMD5.clone();
                } catch (CloneNotSupportedException e) {
                    throw new RuntimeException("MessageDigest does no support clone operation");
                }
            } else {
                md5Clone = JsseJce.getMessageDigest("MD5");
                md5Clone.update(this.md5.archived());
            }
            return md5Clone;
        }

        private MessageDigest cloneSha() {
            MessageDigest shaClone;
            if (this.mdSHA instanceof Cloneable) {
                try {
                    shaClone = (MessageDigest) this.mdSHA.clone();
                } catch (CloneNotSupportedException e) {
                    throw new RuntimeException("MessageDigest does no support clone operation");
                }
            } else {
                shaClone = JsseJce.getMessageDigest("SHA");
                shaClone.update(this.sha.archived());
            }
            return shaClone;
        }

        private static void updateDigest(MessageDigest md, byte[] pad1, byte[] pad2, SecretKey masterSecret) {
            byte[] keyBytes = "RAW".equals(masterSecret.getFormat()) ? masterSecret.getEncoded() : null;
            if (keyBytes != null) {
                md.update(keyBytes);
            } else {
                digestKey(md, masterSecret);
            }
            md.update(pad1);
            byte[] temp = md.digest();
            if (keyBytes != null) {
                md.update(keyBytes);
            } else {
                digestKey(md, masterSecret);
            }
            md.update(pad2);
            md.update(temp);
        }

        private static void digestKey(MessageDigest md, SecretKey key) {
            try {
                if (md instanceof MessageDigestSpi2) {
                    ((MessageDigestSpi2) md).engineUpdate(key);
                    return;
                }
                throw new Exception("Digest does not support implUpdate(SecretKey)");
            } catch (Exception e) {
                throw new RuntimeException("Could not obtain encoded key and MessageDigest cannot digest key", e);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HandshakeHash$T10HandshakeHash.class */
    static final class T10HandshakeHash implements TranscriptHash {
        private final TranscriptHash md5;
        private final TranscriptHash sha;
        private final ByteArrayOutputStream baos;

        T10HandshakeHash(CipherSuite cipherSuite) {
            MessageDigest mdMD5 = JsseJce.getMessageDigest("MD5");
            MessageDigest mdSHA = JsseJce.getMessageDigest("SHA");
            boolean hasArchived = false;
            if (mdMD5 instanceof Cloneable) {
                this.md5 = new CloneableHash(mdMD5);
            } else {
                hasArchived = true;
                this.md5 = new NonCloneableHash(mdMD5);
            }
            if (mdSHA instanceof Cloneable) {
                this.sha = new CloneableHash(mdSHA);
            } else {
                hasArchived = true;
                this.sha = new NonCloneableHash(mdSHA);
            }
            if (hasArchived) {
                this.baos = null;
            } else {
                this.baos = new ByteArrayOutputStream();
            }
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public void update(byte[] input, int offset, int length) {
            this.md5.update(input, offset, length);
            this.sha.update(input, offset, length);
            if (this.baos != null) {
                this.baos.write(input, offset, length);
            }
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public byte[] digest() {
            byte[] digest = new byte[36];
            System.arraycopy(this.md5.digest(), 0, digest, 0, 16);
            System.arraycopy(this.sha.digest(), 0, digest, 16, 20);
            return digest;
        }

        byte[] digest(String algorithm) {
            if ("RSA".equalsIgnoreCase(algorithm)) {
                return digest();
            }
            return this.sha.digest();
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public byte[] archived() {
            if (this.baos != null) {
                return this.baos.toByteArray();
            }
            if (this.md5 instanceof NonCloneableHash) {
                return this.md5.archived();
            }
            return this.sha.archived();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HandshakeHash$T12HandshakeHash.class */
    static final class T12HandshakeHash implements TranscriptHash {
        private final TranscriptHash transcriptHash;
        private final ByteArrayOutputStream baos;

        T12HandshakeHash(CipherSuite cipherSuite) {
            MessageDigest md = JsseJce.getMessageDigest(cipherSuite.hashAlg.name);
            if (md instanceof Cloneable) {
                this.transcriptHash = new CloneableHash(md);
                this.baos = new ByteArrayOutputStream();
                return;
            }
            this.transcriptHash = new NonCloneableHash(md);
            this.baos = null;
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public void update(byte[] input, int offset, int length) {
            this.transcriptHash.update(input, offset, length);
            if (this.baos != null) {
                this.baos.write(input, offset, length);
            }
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public byte[] digest() {
            return this.transcriptHash.digest();
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public byte[] archived() {
            if (this.baos != null) {
                return this.baos.toByteArray();
            }
            return this.transcriptHash.archived();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HandshakeHash$T13HandshakeHash.class */
    static final class T13HandshakeHash implements TranscriptHash {
        private final TranscriptHash transcriptHash;

        T13HandshakeHash(CipherSuite cipherSuite) {
            MessageDigest md = JsseJce.getMessageDigest(cipherSuite.hashAlg.name);
            if (md instanceof Cloneable) {
                this.transcriptHash = new CloneableHash(md);
            } else {
                this.transcriptHash = new NonCloneableHash(md);
            }
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public void update(byte[] input, int offset, int length) {
            this.transcriptHash.update(input, offset, length);
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public byte[] digest() {
            return this.transcriptHash.digest();
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public byte[] archived() {
            throw new UnsupportedOperationException("TLS 1.3 does not require archived.");
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HandshakeHash$CloneableHash.class */
    static final class CloneableHash implements TranscriptHash {

        /* renamed from: md */
        private final MessageDigest f971md;

        CloneableHash(MessageDigest md) {
            this.f971md = md;
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public void update(byte[] input, int offset, int length) {
            this.f971md.update(input, offset, length);
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public byte[] digest() {
            try {
                return ((MessageDigest) this.f971md.clone()).digest();
            } catch (CloneNotSupportedException e) {
                return new byte[0];
            }
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public byte[] archived() {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HandshakeHash$NonCloneableHash.class */
    static final class NonCloneableHash implements TranscriptHash {

        /* renamed from: md */
        private final MessageDigest f972md;
        private final ByteArrayOutputStream baos = new ByteArrayOutputStream();

        NonCloneableHash(MessageDigest md) {
            this.f972md = md;
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public void update(byte[] input, int offset, int length) {
            this.baos.write(input, offset, length);
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public byte[] digest() {
            byte[] bytes = this.baos.toByteArray();
            this.f972md.reset();
            return this.f972md.digest(bytes);
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeHash.TranscriptHash
        public byte[] archived() {
            return this.baos.toByteArray();
        }
    }
}