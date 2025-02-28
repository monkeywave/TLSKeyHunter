package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Objects;
import org.bouncycastle.util.p019io.Streams;

/* loaded from: classes2.dex */
class LMOtsPublicKey implements Encodable {

    /* renamed from: I */
    private final byte[] f1323I;

    /* renamed from: K */
    private final byte[] f1324K;
    private final LMOtsParameters parameter;

    /* renamed from: q */
    private final int f1325q;

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMOtsPublicKey(LMOtsParameters lMOtsParameters, byte[] bArr, int i, byte[] bArr2) {
        this.parameter = lMOtsParameters;
        this.f1323I = bArr;
        this.f1325q = i;
        this.f1324K = bArr2;
    }

    public static LMOtsPublicKey getInstance(Object obj) throws Exception {
        DataInputStream dataInputStream;
        if (obj instanceof LMOtsPublicKey) {
            return (LMOtsPublicKey) obj;
        }
        if (obj instanceof DataInputStream) {
            DataInputStream dataInputStream2 = (DataInputStream) obj;
            LMOtsParameters parametersForType = LMOtsParameters.getParametersForType(dataInputStream2.readInt());
            byte[] bArr = new byte[16];
            dataInputStream2.readFully(bArr);
            int readInt = dataInputStream2.readInt();
            byte[] bArr2 = new byte[parametersForType.getN()];
            dataInputStream2.readFully(bArr2);
            return new LMOtsPublicKey(parametersForType, bArr, readInt, bArr2);
        } else if (!(obj instanceof byte[])) {
            if (obj instanceof InputStream) {
                return getInstance(Streams.readAll((InputStream) obj));
            }
            throw new IllegalArgumentException("cannot parse " + obj);
        } else {
            DataInputStream dataInputStream3 = null;
            try {
                dataInputStream = new DataInputStream(new ByteArrayInputStream((byte[]) obj));
            } catch (Throwable th) {
                th = th;
            }
            try {
                LMOtsPublicKey lMOtsPublicKey = getInstance(dataInputStream);
                dataInputStream.close();
                return lMOtsPublicKey;
            } catch (Throwable th2) {
                th = th2;
                dataInputStream3 = dataInputStream;
                if (dataInputStream3 != null) {
                    dataInputStream3.close();
                }
                throw th;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMSContext createOtsContext(LMOtsSignature lMOtsSignature) {
        Digest digest = DigestUtil.getDigest(this.parameter);
        LmsUtils.byteArray(this.f1323I, digest);
        LmsUtils.u32str(this.f1325q, digest);
        LmsUtils.u16str((short) -32383, digest);
        LmsUtils.byteArray(lMOtsSignature.getC(), digest);
        return new LMSContext(this, lMOtsSignature, digest);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMSContext createOtsContext(LMSSignature lMSSignature) {
        Digest digest = DigestUtil.getDigest(this.parameter);
        LmsUtils.byteArray(this.f1323I, digest);
        LmsUtils.u32str(this.f1325q, digest);
        LmsUtils.u16str((short) -32383, digest);
        LmsUtils.byteArray(lMSSignature.getOtsSignature().getC(), digest);
        return new LMSContext(this, lMSSignature, digest);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        LMOtsPublicKey lMOtsPublicKey = (LMOtsPublicKey) obj;
        return this.f1325q == lMOtsPublicKey.f1325q && Objects.areEqual(this.parameter, lMOtsPublicKey.parameter) && Arrays.areEqual(this.f1323I, lMOtsPublicKey.f1323I) && Arrays.areEqual(this.f1324K, lMOtsPublicKey.f1324K);
    }

    @Override // org.bouncycastle.util.Encodable
    public byte[] getEncoded() throws IOException {
        return Composer.compose().u32str(this.parameter.getType()).bytes(this.f1323I).u32str(this.f1325q).bytes(this.f1324K).build();
    }

    public byte[] getI() {
        return this.f1323I;
    }

    public byte[] getK() {
        return this.f1324K;
    }

    public LMOtsParameters getParameter() {
        return this.parameter;
    }

    public int getQ() {
        return this.f1325q;
    }

    public int hashCode() {
        return (((((this.f1325q * 31) + Objects.hashCode(this.parameter)) * 31) + Arrays.hashCode(this.f1323I)) * 31) + Arrays.hashCode(this.f1324K);
    }
}