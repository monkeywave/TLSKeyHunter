package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.p012io.Streams;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/LMOtsSignature.class */
public class LMOtsSignature implements Encodable {
    private final LMOtsParameters type;

    /* renamed from: C */
    private final byte[] f837C;

    /* renamed from: y */
    private final byte[] f838y;

    public LMOtsSignature(LMOtsParameters lMOtsParameters, byte[] bArr, byte[] bArr2) {
        this.type = lMOtsParameters;
        this.f837C = bArr;
        this.f838y = bArr2;
    }

    public static LMOtsSignature getInstance(Object obj) throws IOException {
        if (obj instanceof LMOtsSignature) {
            return (LMOtsSignature) obj;
        }
        if (obj instanceof DataInputStream) {
            LMOtsParameters parametersForType = LMOtsParameters.getParametersForType(((DataInputStream) obj).readInt());
            byte[] bArr = new byte[parametersForType.getN()];
            ((DataInputStream) obj).readFully(bArr);
            byte[] bArr2 = new byte[parametersForType.getP() * parametersForType.getN()];
            ((DataInputStream) obj).readFully(bArr2);
            return new LMOtsSignature(parametersForType, bArr, bArr2);
        } else if (!(obj instanceof byte[])) {
            if (obj instanceof InputStream) {
                return getInstance(Streams.readAll((InputStream) obj));
            }
            throw new IllegalArgumentException("cannot parse " + obj);
        } else {
            DataInputStream dataInputStream = null;
            try {
                dataInputStream = new DataInputStream(new ByteArrayInputStream((byte[]) obj));
                LMOtsSignature lMOtsSignature = getInstance(dataInputStream);
                if (dataInputStream != null) {
                    dataInputStream.close();
                }
                return lMOtsSignature;
            } catch (Throwable th) {
                if (dataInputStream != null) {
                    dataInputStream.close();
                }
                throw th;
            }
        }
    }

    public LMOtsParameters getType() {
        return this.type;
    }

    public byte[] getC() {
        return this.f837C;
    }

    public byte[] getY() {
        return this.f838y;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        LMOtsSignature lMOtsSignature = (LMOtsSignature) obj;
        if (this.type != null) {
            if (!this.type.equals(lMOtsSignature.type)) {
                return false;
            }
        } else if (lMOtsSignature.type != null) {
            return false;
        }
        if (Arrays.equals(this.f837C, lMOtsSignature.f837C)) {
            return Arrays.equals(this.f838y, lMOtsSignature.f838y);
        }
        return false;
    }

    public int hashCode() {
        return (31 * ((31 * (this.type != null ? this.type.hashCode() : 0)) + Arrays.hashCode(this.f837C))) + Arrays.hashCode(this.f838y);
    }

    @Override // org.bouncycastle.util.Encodable
    public byte[] getEncoded() throws IOException {
        return Composer.compose().u32str(this.type.getType()).bytes(this.f837C).bytes(this.f838y).build();
    }
}