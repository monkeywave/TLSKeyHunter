package org.bouncycastle.pqc.crypto.hqc;

import androidx.constraintlayout.core.motion.utils.TypedValues;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.pqc.crypto.KEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMEngine;
import org.bouncycastle.tls.CipherSuite;

/* loaded from: classes2.dex */
public class HQCParameters implements KEMParameters {
    static final int GF_MUL_ORDER = 255;
    static final int PARAM_M = 8;
    public static final HQCParameters hqc128 = new HQCParameters("hqc-128", 17669, 46, MLKEMEngine.KyberPolyBytes, 16, 31, 15, 66, 75, 75, 16767881, 4, new int[]{89, 69, CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA, 116, CipherSuite.TLS_PSK_WITH_NULL_SHA256, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384, 67, 118, CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256, 210, CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256, 110, 74, 69, 228, 82, 255, CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384, 1});
    public static final HQCParameters hqc192 = new HQCParameters("hqc-192", 35851, 56, 640, 24, 33, 16, 100, 114, 114, 16742417, 5, new int[]{45, 216, 239, 24, 253, 104, 27, 40, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, 50, CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384, 210, 227, CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA, BERTags.FLAGS, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, 119, 13, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, 1, 238, CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256, 82, 43, 15, 232, 246, CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA, 50, CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256, 29, 232, 1});
    public static final HQCParameters hqc256 = new HQCParameters("hqc-256", 57637, 90, 640, 32, 59, 29, 131, CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA, CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA, 16772367, 5, new int[]{49, CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384, 49, 39, 200, 121, 124, 91, 240, 63, CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA, 71, CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA, 123, 87, TypedValues.TYPE_TARGET, 32, 215, CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, 71, 201, 115, 97, 210, CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256, CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA, 217, 123, 12, 31, 243, CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256, 219, CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA, 239, 99, CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA, 4, 246, CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA, 8, 232, 47, 27, CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, 130, 64, 124, 47, 39, 188, 216, 48, CipherSuite.TLS_SM4_CCM_SM3, CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256, 1});
    private int delta;
    private int fft;

    /* renamed from: g */
    private int f1305g;
    private int[] generatorPoly;
    private HQCEngine hqcEngine;

    /* renamed from: k */
    private int f1306k;

    /* renamed from: n */
    private int f1307n;

    /* renamed from: n1 */
    private int f1308n1;

    /* renamed from: n2 */
    private int f1309n2;
    private final String name;
    private int utilRejectionThreshold;

    /* renamed from: w */
    private int f1310w;

    /* renamed from: we */
    private int f1311we;

    /* renamed from: wr */
    private int f1312wr;

    private HQCParameters(String str, int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8, int i9, int i10, int i11, int[] iArr) {
        this.name = str;
        this.f1307n = i;
        this.f1308n1 = i2;
        this.f1309n2 = i3;
        this.f1306k = i4;
        this.delta = i6;
        this.f1310w = i7;
        this.f1312wr = i8;
        this.f1311we = i9;
        this.generatorPoly = iArr;
        this.f1305g = i5;
        this.utilRejectionThreshold = i10;
        this.fft = i11;
        this.hqcEngine = new HQCEngine(i, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, iArr);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getDelta() {
        return this.delta;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public HQCEngine getEngine() {
        return this.hqcEngine;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getK() {
        return this.f1306k;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getN() {
        return this.f1307n;
    }

    int getN1() {
        return this.f1308n1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getN1N2_BYTES() {
        return ((this.f1308n1 * this.f1309n2) + 7) / 8;
    }

    int getN2() {
        return this.f1309n2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getN_BYTES() {
        return (this.f1307n + 7) / 8;
    }

    public String getName() {
        return this.name;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getSALT_SIZE_BYTES() {
        return 16;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getSHA512_BYTES() {
        return 64;
    }

    public int getSessionKeySize() {
        return this.f1306k * 8;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getW() {
        return this.f1310w;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getWe() {
        return this.f1311we;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getWr() {
        return this.f1312wr;
    }
}