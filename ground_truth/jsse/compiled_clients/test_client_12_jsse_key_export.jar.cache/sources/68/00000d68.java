package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.p012io.Streams;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/LMSPublicKeyParameters.class */
public class LMSPublicKeyParameters extends LMSKeyParameters implements LMSContextBasedVerifier {
    private final LMSigParameters parameterSet;
    private final LMOtsParameters lmOtsType;

    /* renamed from: I */
    private final byte[] f843I;

    /* renamed from: T1 */
    private final byte[] f844T1;

    public LMSPublicKeyParameters(LMSigParameters lMSigParameters, LMOtsParameters lMOtsParameters, byte[] bArr, byte[] bArr2) {
        super(false);
        this.parameterSet = lMSigParameters;
        this.lmOtsType = lMOtsParameters;
        this.f843I = Arrays.clone(bArr2);
        this.f844T1 = Arrays.clone(bArr);
    }

    public static LMSPublicKeyParameters getInstance(Object obj) throws IOException {
        if (obj instanceof LMSPublicKeyParameters) {
            return (LMSPublicKeyParameters) obj;
        }
        if (obj instanceof DataInputStream) {
            LMSigParameters parametersForType = LMSigParameters.getParametersForType(((DataInputStream) obj).readInt());
            LMOtsParameters parametersForType2 = LMOtsParameters.getParametersForType(((DataInputStream) obj).readInt());
            byte[] bArr = new byte[16];
            ((DataInputStream) obj).readFully(bArr);
            byte[] bArr2 = new byte[parametersForType.getM()];
            ((DataInputStream) obj).readFully(bArr2);
            return new LMSPublicKeyParameters(parametersForType, parametersForType2, bArr2, bArr);
        } else if (!(obj instanceof byte[])) {
            if (obj instanceof InputStream) {
                return getInstance(Streams.readAll((InputStream) obj));
            }
            throw new IllegalArgumentException("cannot parse " + obj);
        } else {
            DataInputStream dataInputStream = null;
            try {
                dataInputStream = new DataInputStream(new ByteArrayInputStream((byte[]) obj));
                LMSPublicKeyParameters lMSPublicKeyParameters = getInstance(dataInputStream);
                if (dataInputStream != null) {
                    dataInputStream.close();
                }
                return lMSPublicKeyParameters;
            } catch (Throwable th) {
                if (dataInputStream != null) {
                    dataInputStream.close();
                }
                throw th;
            }
        }
    }

    @Override // org.bouncycastle.pqc.crypto.lms.LMSKeyParameters, org.bouncycastle.util.Encodable
    public byte[] getEncoded() throws IOException {
        return toByteArray();
    }

    public LMSigParameters getSigParameters() {
        return this.parameterSet;
    }

    public LMOtsParameters getOtsParameters() {
        return this.lmOtsType;
    }

    public LMSParameters getLMSParameters() {
        return new LMSParameters(getSigParameters(), getOtsParameters());
    }

    public byte[] getT1() {
        return Arrays.clone(this.f844T1);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean matchesT1(byte[] bArr) {
        return Arrays.constantTimeAreEqual(this.f844T1, bArr);
    }

    public byte[] getI() {
        return Arrays.clone(this.f843I);
    }

    byte[] refI() {
        return this.f843I;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        LMSPublicKeyParameters lMSPublicKeyParameters = (LMSPublicKeyParameters) obj;
        if (this.parameterSet.equals(lMSPublicKeyParameters.parameterSet) && this.lmOtsType.equals(lMSPublicKeyParameters.lmOtsType) && Arrays.areEqual(this.f843I, lMSPublicKeyParameters.f843I)) {
            return Arrays.areEqual(this.f844T1, lMSPublicKeyParameters.f844T1);
        }
        return false;
    }

    public int hashCode() {
        return (31 * ((31 * ((31 * this.parameterSet.hashCode()) + this.lmOtsType.hashCode())) + Arrays.hashCode(this.f843I))) + Arrays.hashCode(this.f844T1);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] toByteArray() {
        return Composer.compose().u32str(this.parameterSet.getType()).u32str(this.lmOtsType.getType()).bytes(this.f843I).bytes(this.f844T1).build();
    }

    @Override // org.bouncycastle.pqc.crypto.lms.LMSContextBasedVerifier
    public LMSContext generateLMSContext(byte[] bArr) {
        try {
            return generateOtsContext(LMSSignature.getInstance(bArr));
        } catch (IOException e) {
            throw new IllegalStateException("cannot parse signature: " + e.getMessage());
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMSContext generateOtsContext(LMSSignature lMSSignature) {
        int type = getOtsParameters().getType();
        if (lMSSignature.getOtsSignature().getType().getType() != type) {
            throw new IllegalArgumentException("ots type from lsm signature does not match ots signature type from embedded ots signature");
        }
        return new LMOtsPublicKey(LMOtsParameters.getParametersForType(type), this.f843I, lMSSignature.getQ(), null).createOtsContext(lMSSignature);
    }

    @Override // org.bouncycastle.pqc.crypto.lms.LMSContextBasedVerifier
    public boolean verify(LMSContext lMSContext) {
        return LMS.verifySignature(this, lMSContext);
    }
}