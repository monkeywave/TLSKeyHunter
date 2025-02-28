package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.p012io.Streams;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/LMOtsPublicKey.class */
class LMOtsPublicKey implements Encodable {
    private final LMOtsParameters parameter;

    /* renamed from: I */
    private final byte[] f834I;

    /* renamed from: q */
    private final int f835q;

    /* renamed from: K */
    private final byte[] f836K;

    public LMOtsPublicKey(LMOtsParameters lMOtsParameters, byte[] bArr, int i, byte[] bArr2) {
        this.parameter = lMOtsParameters;
        this.f834I = bArr;
        this.f835q = i;
        this.f836K = bArr2;
    }

    public static LMOtsPublicKey getInstance(Object obj) throws Exception {
        if (obj instanceof LMOtsPublicKey) {
            return (LMOtsPublicKey) obj;
        }
        if (obj instanceof DataInputStream) {
            LMOtsParameters parametersForType = LMOtsParameters.getParametersForType(((DataInputStream) obj).readInt());
            byte[] bArr = new byte[16];
            ((DataInputStream) obj).readFully(bArr);
            int readInt = ((DataInputStream) obj).readInt();
            byte[] bArr2 = new byte[parametersForType.getN()];
            ((DataInputStream) obj).readFully(bArr2);
            return new LMOtsPublicKey(parametersForType, bArr, readInt, bArr2);
        } else if (!(obj instanceof byte[])) {
            if (obj instanceof InputStream) {
                return getInstance(Streams.readAll((InputStream) obj));
            }
            throw new IllegalArgumentException("cannot parse " + obj);
        } else {
            DataInputStream dataInputStream = null;
            try {
                dataInputStream = new DataInputStream(new ByteArrayInputStream((byte[]) obj));
                LMOtsPublicKey lMOtsPublicKey = getInstance(dataInputStream);
                if (dataInputStream != null) {
                    dataInputStream.close();
                }
                return lMOtsPublicKey;
            } catch (Throwable th) {
                if (dataInputStream != null) {
                    dataInputStream.close();
                }
                throw th;
            }
        }
    }

    public LMOtsParameters getParameter() {
        return this.parameter;
    }

    public byte[] getI() {
        return this.f834I;
    }

    public int getQ() {
        return this.f835q;
    }

    public byte[] getK() {
        return this.f836K;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        LMOtsPublicKey lMOtsPublicKey = (LMOtsPublicKey) obj;
        if (this.f835q != lMOtsPublicKey.f835q) {
            return false;
        }
        if (this.parameter != null) {
            if (!this.parameter.equals(lMOtsPublicKey.parameter)) {
                return false;
            }
        } else if (lMOtsPublicKey.parameter != null) {
            return false;
        }
        if (Arrays.equals(this.f834I, lMOtsPublicKey.f834I)) {
            return Arrays.equals(this.f836K, lMOtsPublicKey.f836K);
        }
        return false;
    }

    public int hashCode() {
        return (31 * ((31 * ((31 * (this.parameter != null ? this.parameter.hashCode() : 0)) + Arrays.hashCode(this.f834I))) + this.f835q)) + Arrays.hashCode(this.f836K);
    }

    @Override // org.bouncycastle.util.Encodable
    public byte[] getEncoded() throws IOException {
        return Composer.compose().u32str(this.parameter.getType()).bytes(this.f834I).u32str(this.f835q).bytes(this.f836K).build();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMSContext createOtsContext(LMOtsSignature lMOtsSignature) {
        Digest digest = DigestUtil.getDigest(this.parameter.getDigestOID());
        LmsUtils.byteArray(this.f834I, digest);
        LmsUtils.u32str(this.f835q, digest);
        LmsUtils.u16str((short) -32383, digest);
        LmsUtils.byteArray(lMOtsSignature.getC(), digest);
        return new LMSContext(this, lMOtsSignature, digest);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMSContext createOtsContext(LMSSignature lMSSignature) {
        Digest digest = DigestUtil.getDigest(this.parameter.getDigestOID());
        LmsUtils.byteArray(this.f834I, digest);
        LmsUtils.u32str(this.f835q, digest);
        LmsUtils.u16str((short) -32383, digest);
        LmsUtils.byteArray(lMSSignature.getOtsSignature().getC(), digest);
        return new LMSContext(this, lMSSignature, digest);
    }
}