package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.p012io.Streams;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/LMSSignature.class */
public class LMSSignature implements Encodable {

    /* renamed from: q */
    private final int f845q;
    private final LMOtsSignature otsSignature;
    private final LMSigParameters parameter;

    /* renamed from: y */
    private final byte[][] f846y;

    public LMSSignature(int i, LMOtsSignature lMOtsSignature, LMSigParameters lMSigParameters, byte[][] bArr) {
        this.f845q = i;
        this.otsSignature = lMOtsSignature;
        this.parameter = lMSigParameters;
        this.f846y = bArr;
    }

    /* JADX WARN: Finally extract failed */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v34, types: [byte[], byte[][]] */
    public static LMSSignature getInstance(Object obj) throws IOException {
        if (obj instanceof LMSSignature) {
            return (LMSSignature) obj;
        }
        if (obj instanceof DataInputStream) {
            int readInt = ((DataInputStream) obj).readInt();
            LMOtsSignature lMOtsSignature = LMOtsSignature.getInstance(obj);
            LMSigParameters parametersForType = LMSigParameters.getParametersForType(((DataInputStream) obj).readInt());
            ?? r0 = new byte[parametersForType.getH()];
            for (int i = 0; i < r0.length; i++) {
                r0[i] = new byte[parametersForType.getM()];
                ((DataInputStream) obj).readFully(r0[i]);
            }
            return new LMSSignature(readInt, lMOtsSignature, parametersForType, r0);
        } else if (!(obj instanceof byte[])) {
            if (obj instanceof InputStream) {
                return getInstance(Streams.readAll((InputStream) obj));
            }
            throw new IllegalArgumentException("cannot parse " + obj);
        } else {
            DataInputStream dataInputStream = null;
            try {
                dataInputStream = new DataInputStream(new ByteArrayInputStream((byte[]) obj));
                LMSSignature lMSSignature = getInstance(dataInputStream);
                if (dataInputStream != null) {
                    dataInputStream.close();
                }
                return lMSSignature;
            } catch (Throwable th) {
                if (dataInputStream != null) {
                    dataInputStream.close();
                }
                throw th;
            }
        }
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        LMSSignature lMSSignature = (LMSSignature) obj;
        if (this.f845q != lMSSignature.f845q) {
            return false;
        }
        if (this.otsSignature != null) {
            if (!this.otsSignature.equals(lMSSignature.otsSignature)) {
                return false;
            }
        } else if (lMSSignature.otsSignature != null) {
            return false;
        }
        if (this.parameter != null) {
            if (!this.parameter.equals(lMSSignature.parameter)) {
                return false;
            }
        } else if (lMSSignature.parameter != null) {
            return false;
        }
        return Arrays.deepEquals(this.f846y, lMSSignature.f846y);
    }

    public int hashCode() {
        return (31 * ((31 * ((31 * this.f845q) + (this.otsSignature != null ? this.otsSignature.hashCode() : 0))) + (this.parameter != null ? this.parameter.hashCode() : 0))) + Arrays.deepHashCode(this.f846y);
    }

    @Override // org.bouncycastle.util.Encodable
    public byte[] getEncoded() throws IOException {
        return Composer.compose().u32str(this.f845q).bytes(this.otsSignature.getEncoded()).u32str(this.parameter.getType()).bytes(this.f846y).build();
    }

    public int getQ() {
        return this.f845q;
    }

    public LMOtsSignature getOtsSignature() {
        return this.otsSignature;
    }

    public LMSigParameters getParameter() {
        return this.parameter;
    }

    public byte[][] getY() {
        return this.f846y;
    }
}