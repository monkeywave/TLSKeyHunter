package org.bouncycastle.pqc.crypto.slhdsa;

import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAEngine;

/* loaded from: classes2.dex */
public class SLHDSAParameters {
    public static final int TYPE_PURE = 0;
    public static final int TYPE_SHA2_256 = 1;
    public static final int TYPE_SHA2_512 = 2;
    public static final int TYPE_SHAKE128 = 3;
    public static final int TYPE_SHAKE256 = 4;
    private final SLHDSAEngineProvider engineProvider;
    private final String name;
    private final int preHashDigest;
    public static final SLHDSAParameters sha2_128f = new SLHDSAParameters("sha2-128f", new Sha2EngineProvider(16, 16, 22, 6, 33, 66), 0);
    public static final SLHDSAParameters sha2_128s = new SLHDSAParameters("sha2-128s", new Sha2EngineProvider(16, 16, 7, 12, 14, 63), 0);
    public static final SLHDSAParameters sha2_192f = new SLHDSAParameters("sha2-192f", new Sha2EngineProvider(24, 16, 22, 8, 33, 66), 0);
    public static final SLHDSAParameters sha2_192s = new SLHDSAParameters("sha2-192s", new Sha2EngineProvider(24, 16, 7, 14, 17, 63), 0);
    public static final SLHDSAParameters sha2_256f = new SLHDSAParameters("sha2-256f", new Sha2EngineProvider(32, 16, 17, 9, 35, 68), 0);
    public static final SLHDSAParameters sha2_256s = new SLHDSAParameters("sha2-256s", new Sha2EngineProvider(32, 16, 8, 14, 22, 64), 0);
    public static final SLHDSAParameters shake_128f = new SLHDSAParameters("shake-128f", new Shake256EngineProvider(16, 16, 22, 6, 33, 66), 0);
    public static final SLHDSAParameters shake_128s = new SLHDSAParameters("shake-128s", new Shake256EngineProvider(16, 16, 7, 12, 14, 63), 0);
    public static final SLHDSAParameters shake_192f = new SLHDSAParameters("shake-192f", new Shake256EngineProvider(24, 16, 22, 8, 33, 66), 0);
    public static final SLHDSAParameters shake_192s = new SLHDSAParameters("shake-192s", new Shake256EngineProvider(24, 16, 7, 14, 17, 63), 0);
    public static final SLHDSAParameters shake_256f = new SLHDSAParameters("shake-256f", new Shake256EngineProvider(32, 16, 17, 9, 35, 68), 0);
    public static final SLHDSAParameters shake_256s = new SLHDSAParameters("shake-256s", new Shake256EngineProvider(32, 16, 8, 14, 22, 64), 0);
    public static final SLHDSAParameters sha2_128f_with_sha256 = new SLHDSAParameters("sha2-128f-with-sha256", new Sha2EngineProvider(16, 16, 22, 6, 33, 66), 1);
    public static final SLHDSAParameters sha2_128s_with_sha256 = new SLHDSAParameters("sha2-128s-with-sha256", new Sha2EngineProvider(16, 16, 7, 12, 14, 63), 1);
    public static final SLHDSAParameters sha2_192f_with_sha512 = new SLHDSAParameters("sha2-192f-with-sha512", new Sha2EngineProvider(24, 16, 22, 8, 33, 66), 2);
    public static final SLHDSAParameters sha2_192s_with_sha512 = new SLHDSAParameters("sha2-192s-with-sha512", new Sha2EngineProvider(24, 16, 7, 14, 17, 63), 2);
    public static final SLHDSAParameters sha2_256f_with_sha512 = new SLHDSAParameters("sha2-256f-with-sha512", new Sha2EngineProvider(32, 16, 17, 9, 35, 68), 2);
    public static final SLHDSAParameters sha2_256s_with_sha512 = new SLHDSAParameters("sha2-256s-with-sha512", new Sha2EngineProvider(32, 16, 8, 14, 22, 64), 2);
    public static final SLHDSAParameters shake_128f_with_shake128 = new SLHDSAParameters("shake-128f-with-shake128", new Shake256EngineProvider(16, 16, 22, 6, 33, 66), 3);
    public static final SLHDSAParameters shake_128s_with_shake128 = new SLHDSAParameters("shake-128s-with-shake128", new Shake256EngineProvider(16, 16, 7, 12, 14, 63), 3);
    public static final SLHDSAParameters shake_192f_with_shake256 = new SLHDSAParameters("shake-192f-with-shake256", new Shake256EngineProvider(24, 16, 22, 8, 33, 66), 4);
    public static final SLHDSAParameters shake_192s_with_shake256 = new SLHDSAParameters("shake-192s-with-shake256", new Shake256EngineProvider(24, 16, 7, 14, 17, 63), 4);
    public static final SLHDSAParameters shake_256f_with_shake256 = new SLHDSAParameters("shake-256f-with-shake256", new Shake256EngineProvider(32, 16, 17, 9, 35, 68), 4);
    public static final SLHDSAParameters shake_256s_with_shake256 = new SLHDSAParameters("shake-256s-with-shake256", new Shake256EngineProvider(32, 16, 8, 14, 22, 64), 4);

    /* loaded from: classes2.dex */
    private static class Sha2EngineProvider implements SLHDSAEngineProvider {

        /* renamed from: a */
        private final int f1407a;

        /* renamed from: d */
        private final int f1408d;

        /* renamed from: h */
        private final int f1409h;

        /* renamed from: k */
        private final int f1410k;

        /* renamed from: n */
        private final int f1411n;

        /* renamed from: w */
        private final int f1412w;

        public Sha2EngineProvider(int i, int i2, int i3, int i4, int i5, int i6) {
            this.f1411n = i;
            this.f1412w = i2;
            this.f1408d = i3;
            this.f1407a = i4;
            this.f1410k = i5;
            this.f1409h = i6;
        }

        @Override // org.bouncycastle.pqc.crypto.slhdsa.SLHDSAEngineProvider
        public SLHDSAEngine get() {
            return new SLHDSAEngine.Sha2Engine(this.f1411n, this.f1412w, this.f1408d, this.f1407a, this.f1410k, this.f1409h);
        }

        @Override // org.bouncycastle.pqc.crypto.slhdsa.SLHDSAEngineProvider
        public int getN() {
            return this.f1411n;
        }
    }

    /* loaded from: classes2.dex */
    private static class Shake256EngineProvider implements SLHDSAEngineProvider {

        /* renamed from: a */
        private final int f1413a;

        /* renamed from: d */
        private final int f1414d;

        /* renamed from: h */
        private final int f1415h;

        /* renamed from: k */
        private final int f1416k;

        /* renamed from: n */
        private final int f1417n;

        /* renamed from: w */
        private final int f1418w;

        public Shake256EngineProvider(int i, int i2, int i3, int i4, int i5, int i6) {
            this.f1417n = i;
            this.f1418w = i2;
            this.f1414d = i3;
            this.f1413a = i4;
            this.f1416k = i5;
            this.f1415h = i6;
        }

        @Override // org.bouncycastle.pqc.crypto.slhdsa.SLHDSAEngineProvider
        public SLHDSAEngine get() {
            return new SLHDSAEngine.Shake256Engine(this.f1417n, this.f1418w, this.f1414d, this.f1413a, this.f1416k, this.f1415h);
        }

        @Override // org.bouncycastle.pqc.crypto.slhdsa.SLHDSAEngineProvider
        public int getN() {
            return this.f1417n;
        }
    }

    private SLHDSAParameters(String str, SLHDSAEngineProvider sLHDSAEngineProvider, int i) {
        this.name = str;
        this.engineProvider = sLHDSAEngineProvider;
        this.preHashDigest = i;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SLHDSAEngine getEngine() {
        return this.engineProvider.get();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getN() {
        return this.engineProvider.getN();
    }

    public String getName() {
        return this.name;
    }

    public int getType() {
        return this.preHashDigest;
    }

    public boolean isPreHash() {
        return this.preHashDigest != 0;
    }
}