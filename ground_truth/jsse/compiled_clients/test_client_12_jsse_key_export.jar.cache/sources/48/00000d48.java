package org.bouncycastle.pqc.crypto.gmss;

import java.util.Enumeration;
import java.util.Vector;
import org.bouncycastle.util.Arrays;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/gmss/GMSSUtils.class */
public class GMSSUtils {
    GMSSUtils() {
    }

    static GMSSLeaf[] clone(GMSSLeaf[] gMSSLeafArr) {
        if (gMSSLeafArr == null) {
            return null;
        }
        GMSSLeaf[] gMSSLeafArr2 = new GMSSLeaf[gMSSLeafArr.length];
        System.arraycopy(gMSSLeafArr, 0, gMSSLeafArr2, 0, gMSSLeafArr.length);
        return gMSSLeafArr2;
    }

    static GMSSRootCalc[] clone(GMSSRootCalc[] gMSSRootCalcArr) {
        if (gMSSRootCalcArr == null) {
            return null;
        }
        GMSSRootCalc[] gMSSRootCalcArr2 = new GMSSRootCalc[gMSSRootCalcArr.length];
        System.arraycopy(gMSSRootCalcArr, 0, gMSSRootCalcArr2, 0, gMSSRootCalcArr.length);
        return gMSSRootCalcArr2;
    }

    static GMSSRootSig[] clone(GMSSRootSig[] gMSSRootSigArr) {
        if (gMSSRootSigArr == null) {
            return null;
        }
        GMSSRootSig[] gMSSRootSigArr2 = new GMSSRootSig[gMSSRootSigArr.length];
        System.arraycopy(gMSSRootSigArr, 0, gMSSRootSigArr2, 0, gMSSRootSigArr.length);
        return gMSSRootSigArr2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Type inference failed for: r0v3, types: [byte[], byte[][]] */
    public static byte[][] clone(byte[][] bArr) {
        if (bArr == null) {
            return null;
        }
        ?? r0 = new byte[bArr.length];
        for (int i = 0; i != bArr.length; i++) {
            r0[i] = Arrays.clone(bArr[i]);
        }
        return r0;
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [byte[][], byte[][][]] */
    static byte[][][] clone(byte[][][] bArr) {
        if (bArr == null) {
            return null;
        }
        ?? r0 = new byte[bArr.length];
        for (int i = 0; i != bArr.length; i++) {
            r0[i] = clone(bArr[i]);
        }
        return r0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Treehash[] clone(Treehash[] treehashArr) {
        if (treehashArr == null) {
            return null;
        }
        Treehash[] treehashArr2 = new Treehash[treehashArr.length];
        System.arraycopy(treehashArr, 0, treehashArr2, 0, treehashArr.length);
        return treehashArr2;
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [org.bouncycastle.pqc.crypto.gmss.Treehash[], org.bouncycastle.pqc.crypto.gmss.Treehash[][]] */
    static Treehash[][] clone(Treehash[][] treehashArr) {
        if (treehashArr == null) {
            return null;
        }
        ?? r0 = new Treehash[treehashArr.length];
        for (int i = 0; i != treehashArr.length; i++) {
            r0[i] = clone(treehashArr[i]);
        }
        return r0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Vector[] clone(Vector[] vectorArr) {
        if (vectorArr == null) {
            return null;
        }
        Vector[] vectorArr2 = new Vector[vectorArr.length];
        for (int i = 0; i != vectorArr.length; i++) {
            vectorArr2[i] = new Vector();
            Enumeration elements = vectorArr[i].elements();
            while (elements.hasMoreElements()) {
                vectorArr2[i].addElement(elements.nextElement());
            }
        }
        return vectorArr2;
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [java.util.Vector[], java.util.Vector[][]] */
    static Vector[][] clone(Vector[][] vectorArr) {
        if (vectorArr == null) {
            return null;
        }
        ?? r0 = new Vector[vectorArr.length];
        for (int i = 0; i != vectorArr.length; i++) {
            r0[i] = clone(vectorArr[i]);
        }
        return r0;
    }
}