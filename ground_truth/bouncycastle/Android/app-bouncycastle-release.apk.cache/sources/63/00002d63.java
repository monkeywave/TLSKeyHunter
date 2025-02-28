package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsHashOutputStream;
import org.bouncycastle.tls.crypto.TlsSecret;

/* loaded from: classes2.dex */
public class OfferedPsks {
    protected final Vector binders;
    protected final int bindersSize;
    protected final Vector identities;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public static class BindersConfig {
        final int bindersSize;
        final TlsSecret[] earlySecrets;
        final short[] pskKeyExchangeModes;
        final TlsPSK[] psks;

        /* JADX INFO: Access modifiers changed from: package-private */
        public BindersConfig(TlsPSK[] tlsPSKArr, short[] sArr, TlsSecret[] tlsSecretArr, int i) {
            this.psks = tlsPSKArr;
            this.pskKeyExchangeModes = sArr;
            this.earlySecrets = tlsSecretArr;
            this.bindersSize = i;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public static class SelectedConfig {
        final TlsSecret earlySecret;
        final int index;
        final TlsPSK psk;
        final short[] pskKeyExchangeModes;

        /* JADX INFO: Access modifiers changed from: package-private */
        public SelectedConfig(int i, TlsPSK tlsPSK, short[] sArr, TlsSecret tlsSecret) {
            this.index = i;
            this.psk = tlsPSK;
            this.pskKeyExchangeModes = sArr;
            this.earlySecret = tlsSecret;
        }
    }

    public OfferedPsks(Vector vector) {
        this(vector, null, -1);
    }

    private OfferedPsks(Vector vector, Vector vector2, int i) {
        if (vector == null || vector.isEmpty()) {
            throw new IllegalArgumentException("'identities' cannot be null or empty");
        }
        if (vector2 != null && vector.size() != vector2.size()) {
            throw new IllegalArgumentException("'binders' must be the same length as 'identities' (or null)");
        }
        if ((vector2 != null) != (i >= 0)) {
            throw new IllegalArgumentException("'bindersSize' must be >= 0 iff 'binders' are present");
        }
        this.identities = vector;
        this.binders = vector2;
        this.bindersSize = i;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void encodeBinders(OutputStream outputStream, TlsCrypto tlsCrypto, TlsHandshakeHash tlsHandshakeHash, BindersConfig bindersConfig) throws IOException {
        TlsPSK[] tlsPSKArr = bindersConfig.psks;
        TlsSecret[] tlsSecretArr = bindersConfig.earlySecrets;
        int i = bindersConfig.bindersSize - 2;
        TlsUtils.checkUint16(i);
        TlsUtils.writeUint16(i, outputStream);
        int i2 = 0;
        for (int i3 = 0; i3 < tlsPSKArr.length; i3++) {
            TlsPSK tlsPSK = tlsPSKArr[i3];
            TlsSecret tlsSecret = tlsSecretArr[i3];
            int hashForPRF = TlsCryptoUtils.getHashForPRF(tlsPSK.getPRFAlgorithm());
            TlsHash createHash = tlsCrypto.createHash(hashForPRF);
            tlsHandshakeHash.copyBufferTo(new TlsHashOutputStream(createHash));
            byte[] calculatePSKBinder = TlsUtils.calculatePSKBinder(tlsCrypto, true, hashForPRF, tlsSecret, createHash.calculateHash());
            i2 += calculatePSKBinder.length + 1;
            TlsUtils.writeOpaque8(calculatePSKBinder, outputStream);
        }
        if (i != i2) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getBindersSize(TlsPSK[] tlsPSKArr) throws IOException {
        int i = 0;
        for (TlsPSK tlsPSK : tlsPSKArr) {
            i += TlsCryptoUtils.getHashOutputSize(TlsCryptoUtils.getHashForPRF(tlsPSK.getPRFAlgorithm())) + 1;
        }
        TlsUtils.checkUint16(i);
        return i + 2;
    }

    public static OfferedPsks parse(InputStream inputStream) throws IOException {
        Vector vector = new Vector();
        int readUint16 = TlsUtils.readUint16(inputStream);
        if (readUint16 >= 7) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(TlsUtils.readFully(readUint16, inputStream));
            do {
                vector.add(PskIdentity.parse(byteArrayInputStream));
            } while (byteArrayInputStream.available() > 0);
            Vector vector2 = new Vector();
            int readUint162 = TlsUtils.readUint16(inputStream);
            if (readUint162 >= 33) {
                ByteArrayInputStream byteArrayInputStream2 = new ByteArrayInputStream(TlsUtils.readFully(readUint162, inputStream));
                do {
                    vector2.add(TlsUtils.readOpaque8(byteArrayInputStream2, 32));
                } while (byteArrayInputStream2.available() > 0);
                return new OfferedPsks(vector, vector2, readUint162 + 2);
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new TlsFatalAlert((short) 50);
    }

    public void encode(OutputStream outputStream) throws IOException {
        int i = 0;
        for (int i2 = 0; i2 < this.identities.size(); i2++) {
            i += ((PskIdentity) this.identities.elementAt(i2)).getEncodedLength();
        }
        TlsUtils.checkUint16(i);
        TlsUtils.writeUint16(i, outputStream);
        for (int i3 = 0; i3 < this.identities.size(); i3++) {
            ((PskIdentity) this.identities.elementAt(i3)).encode(outputStream);
        }
        if (this.binders != null) {
            int i4 = 0;
            for (int i5 = 0; i5 < this.binders.size(); i5++) {
                i4 += ((byte[]) this.binders.elementAt(i5)).length + 1;
            }
            TlsUtils.checkUint16(i4);
            TlsUtils.writeUint16(i4, outputStream);
            for (int i6 = 0; i6 < this.binders.size(); i6++) {
                TlsUtils.writeOpaque8((byte[]) this.binders.elementAt(i6), outputStream);
            }
        }
    }

    public Vector getBinders() {
        return this.binders;
    }

    public int getBindersSize() {
        return this.bindersSize;
    }

    public Vector getIdentities() {
        return this.identities;
    }

    public int getIndexOfIdentity(PskIdentity pskIdentity) {
        int size = this.identities.size();
        for (int i = 0; i < size; i++) {
            if (pskIdentity.equals(this.identities.elementAt(i))) {
                return i;
            }
        }
        return -1;
    }
}