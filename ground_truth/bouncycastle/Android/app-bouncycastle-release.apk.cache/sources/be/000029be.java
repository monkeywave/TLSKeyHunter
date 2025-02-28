package org.bouncycastle.pqc.crypto.gemss;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class SecretKeyHFE {
    public Pointer F_HFEv;
    complete_sparse_monic_gf2nx F_struct;

    /* renamed from: S */
    public Pointer f1288S;

    /* renamed from: T */
    public Pointer f1289T;
    public Pointer sk_uncomp;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public static class complete_sparse_monic_gf2nx {

        /* renamed from: L */
        public int[] f1290L;
        public Pointer poly;
    }

    public SecretKeyHFE(GeMSSEngine geMSSEngine) {
        complete_sparse_monic_gf2nx complete_sparse_monic_gf2nxVar = new complete_sparse_monic_gf2nx();
        this.F_struct = complete_sparse_monic_gf2nxVar;
        complete_sparse_monic_gf2nxVar.f1290L = new int[geMSSEngine.NB_COEFS_HFEPOLY];
    }
}