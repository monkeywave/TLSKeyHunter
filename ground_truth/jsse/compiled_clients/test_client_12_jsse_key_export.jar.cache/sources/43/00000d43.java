package org.bouncycastle.pqc.crypto.gmss;

import java.util.Enumeration;
import java.util.Vector;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/gmss/GMSSRootCalc.class */
public class GMSSRootCalc {
    private int heightOfTree;
    private int mdLength;
    private Treehash[] treehash;
    private Vector[] retain;
    private byte[] root;
    private byte[][] AuthPath;

    /* renamed from: K */
    private int f819K;
    private Vector tailStack;
    private Vector heightOfNodes;
    private Digest messDigestTree;
    private GMSSDigestProvider digestProvider;
    private int[] index;
    private boolean isInitialized;
    private boolean isFinished;
    private int indexForNextSeed;
    private int heightOfNextSeed;

    public GMSSRootCalc(int i, int i2, GMSSDigestProvider gMSSDigestProvider) {
        this.heightOfTree = i;
        this.digestProvider = gMSSDigestProvider;
        this.messDigestTree = gMSSDigestProvider.get();
        this.mdLength = this.messDigestTree.getDigestSize();
        this.f819K = i2;
        this.index = new int[i];
        this.AuthPath = new byte[i][this.mdLength];
        this.root = new byte[this.mdLength];
        this.retain = new Vector[this.f819K - 1];
        for (int i3 = 0; i3 < i2 - 1; i3++) {
            this.retain[i3] = new Vector();
        }
    }

    public void initialize(Vector vector) {
        this.treehash = new Treehash[this.heightOfTree - this.f819K];
        for (int i = 0; i < this.heightOfTree - this.f819K; i++) {
            this.treehash[i] = new Treehash(vector, i, this.digestProvider.get());
        }
        this.index = new int[this.heightOfTree];
        this.AuthPath = new byte[this.heightOfTree][this.mdLength];
        this.root = new byte[this.mdLength];
        this.tailStack = new Vector();
        this.heightOfNodes = new Vector();
        this.isInitialized = true;
        this.isFinished = false;
        for (int i2 = 0; i2 < this.heightOfTree; i2++) {
            this.index[i2] = -1;
        }
        this.retain = new Vector[this.f819K - 1];
        for (int i3 = 0; i3 < this.f819K - 1; i3++) {
            this.retain[i3] = new Vector();
        }
        this.indexForNextSeed = 3;
        this.heightOfNextSeed = 0;
    }

    public void update(byte[] bArr, byte[] bArr2) {
        if (this.heightOfNextSeed < this.heightOfTree - this.f819K && this.indexForNextSeed - 2 == this.index[0]) {
            initializeTreehashSeed(bArr, this.heightOfNextSeed);
            this.heightOfNextSeed++;
            this.indexForNextSeed *= 2;
        }
        update(bArr2);
    }

    public void update(byte[] bArr) {
        if (this.isFinished) {
            System.out.print("Too much updates for Tree!!");
        } else if (!this.isInitialized) {
            System.err.println("GMSSRootCalc not initialized!");
        } else {
            int[] iArr = this.index;
            iArr[0] = iArr[0] + 1;
            if (this.index[0] == 1) {
                System.arraycopy(bArr, 0, this.AuthPath[0], 0, this.mdLength);
            } else if (this.index[0] == 3 && this.heightOfTree > this.f819K) {
                this.treehash[0].setFirstNode(bArr);
            }
            if ((this.index[0] - 3) % 2 == 0 && this.index[0] >= 3 && this.heightOfTree == this.f819K) {
                this.retain[0].insertElementAt(bArr, 0);
            }
            if (this.index[0] == 0) {
                this.tailStack.addElement(bArr);
                this.heightOfNodes.addElement(Integers.valueOf(0));
                return;
            }
            byte[] bArr2 = new byte[this.mdLength];
            byte[] bArr3 = new byte[this.mdLength << 1];
            System.arraycopy(bArr, 0, bArr2, 0, this.mdLength);
            int i = 0;
            while (this.tailStack.size() > 0 && i == ((Integer) this.heightOfNodes.lastElement()).intValue()) {
                System.arraycopy(this.tailStack.lastElement(), 0, bArr3, 0, this.mdLength);
                this.tailStack.removeElementAt(this.tailStack.size() - 1);
                this.heightOfNodes.removeElementAt(this.heightOfNodes.size() - 1);
                System.arraycopy(bArr2, 0, bArr3, this.mdLength, this.mdLength);
                this.messDigestTree.update(bArr3, 0, bArr3.length);
                bArr2 = new byte[this.messDigestTree.getDigestSize()];
                this.messDigestTree.doFinal(bArr2, 0);
                i++;
                if (i < this.heightOfTree) {
                    int[] iArr2 = this.index;
                    iArr2[i] = iArr2[i] + 1;
                    if (this.index[i] == 1) {
                        System.arraycopy(bArr2, 0, this.AuthPath[i], 0, this.mdLength);
                    }
                    if (i >= this.heightOfTree - this.f819K) {
                        if (i == 0) {
                            System.out.println("M���P");
                        }
                        if ((this.index[i] - 3) % 2 == 0 && this.index[i] >= 3) {
                            this.retain[i - (this.heightOfTree - this.f819K)].insertElementAt(bArr2, 0);
                        }
                    } else if (this.index[i] == 3) {
                        this.treehash[i].setFirstNode(bArr2);
                    }
                }
            }
            this.tailStack.addElement(bArr2);
            this.heightOfNodes.addElement(Integers.valueOf(i));
            if (i == this.heightOfTree) {
                this.isFinished = true;
                this.isInitialized = false;
                this.root = (byte[]) this.tailStack.lastElement();
            }
        }
    }

    public void initializeTreehashSeed(byte[] bArr, int i) {
        this.treehash[i].initializeSeed(bArr);
    }

    public boolean wasInitialized() {
        return this.isInitialized;
    }

    public boolean wasFinished() {
        return this.isFinished;
    }

    public byte[][] getAuthPath() {
        return GMSSUtils.clone(this.AuthPath);
    }

    public Treehash[] getTreehash() {
        return GMSSUtils.clone(this.treehash);
    }

    public Vector[] getRetain() {
        return GMSSUtils.clone(this.retain);
    }

    public byte[] getRoot() {
        return Arrays.clone(this.root);
    }

    public Vector getStack() {
        Vector vector = new Vector();
        Enumeration elements = this.tailStack.elements();
        while (elements.hasMoreElements()) {
            vector.addElement(elements.nextElement());
        }
        return vector;
    }

    public byte[][] getStatByte() {
        int size = this.tailStack == null ? 0 : this.tailStack.size();
        byte[][] bArr = new byte[1 + this.heightOfTree + size][64];
        bArr[0] = this.root;
        for (int i = 0; i < this.heightOfTree; i++) {
            bArr[1 + i] = this.AuthPath[i];
        }
        for (int i2 = 0; i2 < size; i2++) {
            bArr[1 + this.heightOfTree + i2] = (byte[]) this.tailStack.elementAt(i2);
        }
        return bArr;
    }

    public int[] getStatInt() {
        int size = this.tailStack == null ? 0 : this.tailStack.size();
        int[] iArr = new int[8 + this.heightOfTree + size];
        iArr[0] = this.heightOfTree;
        iArr[1] = this.mdLength;
        iArr[2] = this.f819K;
        iArr[3] = this.indexForNextSeed;
        iArr[4] = this.heightOfNextSeed;
        if (this.isFinished) {
            iArr[5] = 1;
        } else {
            iArr[5] = 0;
        }
        if (this.isInitialized) {
            iArr[6] = 1;
        } else {
            iArr[6] = 0;
        }
        iArr[7] = size;
        for (int i = 0; i < this.heightOfTree; i++) {
            iArr[8 + i] = this.index[i];
        }
        for (int i2 = 0; i2 < size; i2++) {
            iArr[8 + this.heightOfTree + i2] = ((Integer) this.heightOfNodes.elementAt(i2)).intValue();
        }
        return iArr;
    }

    public String toString() {
        String str = "";
        int size = this.tailStack == null ? 0 : this.tailStack.size();
        for (int i = 0; i < 8 + this.heightOfTree + size; i++) {
            str = str + getStatInt()[i] + " ";
        }
        for (int i2 = 0; i2 < 1 + this.heightOfTree + size; i2++) {
            str = str + new String(Hex.encode(getStatByte()[i2])) + " ";
        }
        return str + "  " + this.digestProvider.get().getDigestSize();
    }
}