package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.p019io.Streams;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class LMOtsSignature implements Encodable {

    /* renamed from: C */
    private final byte[] f1326C;
    private final LMOtsParameters type;

    /* renamed from: y */
    private final byte[] f1327y;

    public LMOtsSignature(LMOtsParameters lMOtsParameters, byte[] bArr, byte[] bArr2) {
        this.type = lMOtsParameters;
        this.f1326C = bArr;
        this.f1327y = bArr2;
    }

    public static LMOtsSignature getInstance(Object obj) throws IOException {
        if (obj instanceof LMOtsSignature) {
            return (LMOtsSignature) obj;
        }
        if (obj instanceof DataInputStream) {
            DataInputStream dataInputStream = (DataInputStream) obj;
            LMOtsParameters parametersForType = LMOtsParameters.getParametersForType(dataInputStream.readInt());
            byte[] bArr = new byte[parametersForType.getN()];
            dataInputStream.readFully(bArr);
            byte[] bArr2 = new byte[parametersForType.getP() * parametersForType.getN()];
            dataInputStream.readFully(bArr2);
            return new LMOtsSignature(parametersForType, bArr, bArr2);
        } else if (!(obj instanceof byte[])) {
            if (obj instanceof InputStream) {
                return getInstance(Streams.readAll((InputStream) obj));
            }
            throw new IllegalArgumentException("cannot parse " + obj);
        } else {
            DataInputStream dataInputStream2 = null;
            try {
                DataInputStream dataInputStream3 = new DataInputStream(new ByteArrayInputStream((byte[]) obj));
                try {
                    LMOtsSignature lMOtsSignature = getInstance(dataInputStream3);
                    dataInputStream3.close();
                    return lMOtsSignature;
                } catch (Throwable th) {
                    th = th;
                    dataInputStream2 = dataInputStream3;
                    if (dataInputStream2 != null) {
                        dataInputStream2.close();
                    }
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
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
        LMOtsSignature lMOtsSignature = (LMOtsSignature) obj;
        LMOtsParameters lMOtsParameters = this.type;
        if (lMOtsParameters == null ? lMOtsSignature.type == null : lMOtsParameters.equals(lMOtsSignature.type)) {
            if (Arrays.equals(this.f1326C, lMOtsSignature.f1326C)) {
                return Arrays.equals(this.f1327y, lMOtsSignature.f1327y);
            }
            return false;
        }
        return false;
    }

    public byte[] getC() {
        return this.f1326C;
    }

    @Override // org.bouncycastle.util.Encodable
    public byte[] getEncoded() throws IOException {
        return Composer.compose().u32str(this.type.getType()).bytes(this.f1326C).bytes(this.f1327y).build();
    }

    public LMOtsParameters getType() {
        return this.type;
    }

    public byte[] getY() {
        return this.f1327y;
    }

    public int hashCode() {
        LMOtsParameters lMOtsParameters = this.type;
        return ((((lMOtsParameters != null ? lMOtsParameters.hashCode() : 0) * 31) + Arrays.hashCode(this.f1326C)) * 31) + Arrays.hashCode(this.f1327y);
    }
}