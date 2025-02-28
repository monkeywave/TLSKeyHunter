package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.p012io.Streams;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/HSSSignature.class */
public class HSSSignature implements Encodable {
    private final int lMinus1;
    private final LMSSignedPubKey[] signedPubKey;
    private final LMSSignature signature;

    public HSSSignature(int i, LMSSignedPubKey[] lMSSignedPubKeyArr, LMSSignature lMSSignature) {
        this.lMinus1 = i;
        this.signedPubKey = lMSSignedPubKeyArr;
        this.signature = lMSSignature;
    }

    public static HSSSignature getInstance(Object obj, int i) throws IOException {
        if (obj instanceof HSSSignature) {
            return (HSSSignature) obj;
        }
        if (obj instanceof DataInputStream) {
            int readInt = ((DataInputStream) obj).readInt();
            if (readInt != i - 1) {
                throw new IllegalStateException("nspk exceeded maxNspk");
            }
            LMSSignedPubKey[] lMSSignedPubKeyArr = new LMSSignedPubKey[readInt];
            if (readInt != 0) {
                for (int i2 = 0; i2 < lMSSignedPubKeyArr.length; i2++) {
                    lMSSignedPubKeyArr[i2] = new LMSSignedPubKey(LMSSignature.getInstance(obj), LMSPublicKeyParameters.getInstance(obj));
                }
            }
            return new HSSSignature(readInt, lMSSignedPubKeyArr, LMSSignature.getInstance(obj));
        } else if (!(obj instanceof byte[])) {
            if (obj instanceof InputStream) {
                return getInstance(Streams.readAll((InputStream) obj), i);
            }
            throw new IllegalArgumentException("cannot parse " + obj);
        } else {
            DataInputStream dataInputStream = null;
            try {
                dataInputStream = new DataInputStream(new ByteArrayInputStream((byte[]) obj));
                HSSSignature hSSSignature = getInstance(dataInputStream, i);
                if (dataInputStream != null) {
                    dataInputStream.close();
                }
                return hSSSignature;
            } catch (Throwable th) {
                if (dataInputStream != null) {
                    dataInputStream.close();
                }
                throw th;
            }
        }
    }

    public int getlMinus1() {
        return this.lMinus1;
    }

    public LMSSignedPubKey[] getSignedPubKey() {
        return this.signedPubKey;
    }

    public LMSSignature getSignature() {
        return this.signature;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        HSSSignature hSSSignature = (HSSSignature) obj;
        if (this.lMinus1 == hSSSignature.lMinus1 && this.signedPubKey.length == hSSSignature.signedPubKey.length) {
            for (int i = 0; i < this.signedPubKey.length; i++) {
                if (!this.signedPubKey[i].equals(hSSSignature.signedPubKey[i])) {
                    return false;
                }
            }
            return this.signature != null ? this.signature.equals(hSSSignature.signature) : hSSSignature.signature == null;
        }
        return false;
    }

    public int hashCode() {
        return (31 * ((31 * this.lMinus1) + Arrays.hashCode(this.signedPubKey))) + (this.signature != null ? this.signature.hashCode() : 0);
    }

    @Override // org.bouncycastle.util.Encodable
    public byte[] getEncoded() throws IOException {
        Composer compose = Composer.compose();
        compose.u32str(this.lMinus1);
        if (this.signedPubKey != null) {
            for (LMSSignedPubKey lMSSignedPubKey : this.signedPubKey) {
                compose.bytes(lMSSignedPubKey);
            }
        }
        compose.bytes(this.signature);
        return compose.build();
    }
}