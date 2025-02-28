package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.TreeMap;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.pqc.crypto.xmss.HashTreeAddress;
import org.bouncycastle.pqc.crypto.xmss.LTreeAddress;
import org.bouncycastle.pqc.crypto.xmss.OTSHashAddress;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/xmss/BDS.class */
public final class BDS implements Serializable {
    private static final long serialVersionUID = 1;
    private transient WOTSPlus wotsPlus;
    private final int treeHeight;
    private final List<BDSTreeHash> treeHashInstances;

    /* renamed from: k */
    private int f922k;
    private XMSSNode root;
    private List<XMSSNode> authenticationPath;
    private Map<Integer, LinkedList<XMSSNode>> retain;
    private Stack<XMSSNode> stack;
    private Map<Integer, XMSSNode> keep;
    private int index;
    private boolean used;
    private transient int maxIndex;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BDS(XMSSParameters xMSSParameters, int i, int i2) {
        this(xMSSParameters.getWOTSPlus(), xMSSParameters.getHeight(), xMSSParameters.getK(), i2);
        this.maxIndex = i;
        this.index = i2;
        this.used = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BDS(XMSSParameters xMSSParameters, byte[] bArr, byte[] bArr2, OTSHashAddress oTSHashAddress) {
        this(xMSSParameters.getWOTSPlus(), xMSSParameters.getHeight(), xMSSParameters.getK(), (1 << xMSSParameters.getHeight()) - 1);
        initialize(bArr, bArr2, oTSHashAddress);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BDS(XMSSParameters xMSSParameters, byte[] bArr, byte[] bArr2, OTSHashAddress oTSHashAddress, int i) {
        this(xMSSParameters.getWOTSPlus(), xMSSParameters.getHeight(), xMSSParameters.getK(), (1 << xMSSParameters.getHeight()) - 1);
        initialize(bArr, bArr2, oTSHashAddress);
        while (this.index < i) {
            nextAuthenticationPath(bArr, bArr2, oTSHashAddress);
            this.used = false;
        }
    }

    private BDS(WOTSPlus wOTSPlus, int i, int i2, int i3) {
        this.wotsPlus = wOTSPlus;
        this.treeHeight = i;
        this.maxIndex = i3;
        this.f922k = i2;
        if (i2 > i || i2 < 2 || (i - i2) % 2 != 0) {
            throw new IllegalArgumentException("illegal value for BDS parameter k");
        }
        this.authenticationPath = new ArrayList();
        this.retain = new TreeMap();
        this.stack = new Stack<>();
        this.treeHashInstances = new ArrayList();
        for (int i4 = 0; i4 < i - i2; i4++) {
            this.treeHashInstances.add(new BDSTreeHash(i4));
        }
        this.keep = new TreeMap();
        this.index = 0;
        this.used = false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BDS(BDS bds) {
        this.wotsPlus = new WOTSPlus(bds.wotsPlus.getParams());
        this.treeHeight = bds.treeHeight;
        this.f922k = bds.f922k;
        this.root = bds.root;
        this.authenticationPath = new ArrayList();
        this.authenticationPath.addAll(bds.authenticationPath);
        this.retain = new TreeMap();
        for (Integer num : bds.retain.keySet()) {
            this.retain.put(num, (LinkedList) bds.retain.get(num).clone());
        }
        this.stack = new Stack<>();
        this.stack.addAll(bds.stack);
        this.treeHashInstances = new ArrayList();
        for (BDSTreeHash bDSTreeHash : bds.treeHashInstances) {
            this.treeHashInstances.add(bDSTreeHash.m627clone());
        }
        this.keep = new TreeMap(bds.keep);
        this.index = bds.index;
        this.maxIndex = bds.maxIndex;
        this.used = bds.used;
    }

    private BDS(BDS bds, byte[] bArr, byte[] bArr2, OTSHashAddress oTSHashAddress) {
        this.wotsPlus = new WOTSPlus(bds.wotsPlus.getParams());
        this.treeHeight = bds.treeHeight;
        this.f922k = bds.f922k;
        this.root = bds.root;
        this.authenticationPath = new ArrayList();
        this.authenticationPath.addAll(bds.authenticationPath);
        this.retain = new TreeMap();
        for (Integer num : bds.retain.keySet()) {
            this.retain.put(num, (LinkedList) bds.retain.get(num).clone());
        }
        this.stack = new Stack<>();
        this.stack.addAll(bds.stack);
        this.treeHashInstances = new ArrayList();
        for (BDSTreeHash bDSTreeHash : bds.treeHashInstances) {
            this.treeHashInstances.add(bDSTreeHash.m627clone());
        }
        this.keep = new TreeMap(bds.keep);
        this.index = bds.index;
        this.maxIndex = bds.maxIndex;
        this.used = false;
        nextAuthenticationPath(bArr, bArr2, oTSHashAddress);
    }

    private BDS(BDS bds, ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        this.wotsPlus = new WOTSPlus(new WOTSPlusParameters(aSN1ObjectIdentifier));
        this.treeHeight = bds.treeHeight;
        this.f922k = bds.f922k;
        this.root = bds.root;
        this.authenticationPath = new ArrayList();
        this.authenticationPath.addAll(bds.authenticationPath);
        this.retain = new TreeMap();
        for (Integer num : bds.retain.keySet()) {
            this.retain.put(num, (LinkedList) bds.retain.get(num).clone());
        }
        this.stack = new Stack<>();
        this.stack.addAll(bds.stack);
        this.treeHashInstances = new ArrayList();
        for (BDSTreeHash bDSTreeHash : bds.treeHashInstances) {
            this.treeHashInstances.add(bDSTreeHash.m627clone());
        }
        this.keep = new TreeMap(bds.keep);
        this.index = bds.index;
        this.maxIndex = bds.maxIndex;
        this.used = bds.used;
        validate();
    }

    private BDS(BDS bds, int i, ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        this.wotsPlus = new WOTSPlus(new WOTSPlusParameters(aSN1ObjectIdentifier));
        this.treeHeight = bds.treeHeight;
        this.f922k = bds.f922k;
        this.root = bds.root;
        this.authenticationPath = new ArrayList();
        this.authenticationPath.addAll(bds.authenticationPath);
        this.retain = new TreeMap();
        for (Integer num : bds.retain.keySet()) {
            this.retain.put(num, (LinkedList) bds.retain.get(num).clone());
        }
        this.stack = new Stack<>();
        this.stack.addAll(bds.stack);
        this.treeHashInstances = new ArrayList();
        for (BDSTreeHash bDSTreeHash : bds.treeHashInstances) {
            this.treeHashInstances.add(bDSTreeHash.m627clone());
        }
        this.keep = new TreeMap(bds.keep);
        this.index = bds.index;
        this.maxIndex = i;
        this.used = bds.used;
        validate();
    }

    public BDS getNextState(byte[] bArr, byte[] bArr2, OTSHashAddress oTSHashAddress) {
        return new BDS(this, bArr, bArr2, oTSHashAddress);
    }

    private void initialize(byte[] bArr, byte[] bArr2, OTSHashAddress oTSHashAddress) {
        if (oTSHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }
        LTreeAddress lTreeAddress = (LTreeAddress) new LTreeAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).build();
        HashTreeAddress hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).build();
        for (int i = 0; i < (1 << this.treeHeight); i++) {
            oTSHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).withOTSAddress(i).withChainAddress(oTSHashAddress.getChainAddress()).withHashAddress(oTSHashAddress.getHashAddress()).withKeyAndMask(oTSHashAddress.getKeyAndMask()).build();
            this.wotsPlus.importKeys(this.wotsPlus.getWOTSPlusSecretKey(bArr2, oTSHashAddress), bArr);
            WOTSPlusPublicKeyParameters publicKey = this.wotsPlus.getPublicKey(oTSHashAddress);
            lTreeAddress = (LTreeAddress) new LTreeAddress.Builder().withLayerAddress(lTreeAddress.getLayerAddress()).withTreeAddress(lTreeAddress.getTreeAddress()).withLTreeAddress(i).withTreeHeight(lTreeAddress.getTreeHeight()).withTreeIndex(lTreeAddress.getTreeIndex()).withKeyAndMask(lTreeAddress.getKeyAndMask()).build();
            XMSSNode lTree = XMSSNodeUtil.lTree(this.wotsPlus, publicKey, lTreeAddress);
            XMSSAddress build = new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress.getLayerAddress()).withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeIndex(i).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
            while (true) {
                hashTreeAddress = (HashTreeAddress) build;
                if (!this.stack.isEmpty() && this.stack.peek().getHeight() == lTree.getHeight()) {
                    int height = i / (1 << lTree.getHeight());
                    if (height == 1) {
                        this.authenticationPath.add(lTree);
                    }
                    if (height == 3 && lTree.getHeight() < this.treeHeight - this.f922k) {
                        this.treeHashInstances.get(lTree.getHeight()).setNode(lTree);
                    }
                    if (height >= 3 && (height & 1) == 1 && lTree.getHeight() >= this.treeHeight - this.f922k && lTree.getHeight() <= this.treeHeight - 2) {
                        if (this.retain.get(Integer.valueOf(lTree.getHeight())) == null) {
                            LinkedList<XMSSNode> linkedList = new LinkedList<>();
                            linkedList.add(lTree);
                            this.retain.put(Integer.valueOf(lTree.getHeight()), linkedList);
                        } else {
                            this.retain.get(Integer.valueOf(lTree.getHeight())).add(lTree);
                        }
                    }
                    HashTreeAddress hashTreeAddress2 = (HashTreeAddress) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress.getLayerAddress()).withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(hashTreeAddress.getTreeHeight()).withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
                    XMSSNode randomizeHash = XMSSNodeUtil.randomizeHash(this.wotsPlus, this.stack.pop(), lTree, hashTreeAddress2);
                    lTree = new XMSSNode(randomizeHash.getHeight() + 1, randomizeHash.getValue());
                    build = new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress2.getLayerAddress()).withTreeAddress(hashTreeAddress2.getTreeAddress()).withTreeHeight(hashTreeAddress2.getTreeHeight() + 1).withTreeIndex(hashTreeAddress2.getTreeIndex()).withKeyAndMask(hashTreeAddress2.getKeyAndMask()).build();
                }
            }
            this.stack.push(lTree);
        }
        this.root = this.stack.pop();
    }

    private void nextAuthenticationPath(byte[] bArr, byte[] bArr2, OTSHashAddress oTSHashAddress) {
        if (oTSHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }
        if (this.used) {
            throw new IllegalStateException("index already used");
        }
        if (this.index > this.maxIndex - 1) {
            throw new IllegalStateException("index out of bounds");
        }
        int calculateTau = XMSSUtil.calculateTau(this.index, this.treeHeight);
        if (((this.index >> (calculateTau + 1)) & 1) == 0 && calculateTau < this.treeHeight - 1) {
            this.keep.put(Integer.valueOf(calculateTau), this.authenticationPath.get(calculateTau));
        }
        LTreeAddress lTreeAddress = (LTreeAddress) new LTreeAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).build();
        HashTreeAddress hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).build();
        if (calculateTau == 0) {
            oTSHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).withOTSAddress(this.index).withChainAddress(oTSHashAddress.getChainAddress()).withHashAddress(oTSHashAddress.getHashAddress()).withKeyAndMask(oTSHashAddress.getKeyAndMask()).build();
            this.wotsPlus.importKeys(this.wotsPlus.getWOTSPlusSecretKey(bArr2, oTSHashAddress), bArr);
            this.authenticationPath.set(0, XMSSNodeUtil.lTree(this.wotsPlus, this.wotsPlus.getPublicKey(oTSHashAddress), (LTreeAddress) new LTreeAddress.Builder().withLayerAddress(lTreeAddress.getLayerAddress()).withTreeAddress(lTreeAddress.getTreeAddress()).withLTreeAddress(this.index).withTreeHeight(lTreeAddress.getTreeHeight()).withTreeIndex(lTreeAddress.getTreeIndex()).withKeyAndMask(lTreeAddress.getKeyAndMask()).build()));
        } else {
            HashTreeAddress hashTreeAddress2 = (HashTreeAddress) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress.getLayerAddress()).withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(calculateTau - 1).withTreeIndex(this.index >> calculateTau).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
            this.wotsPlus.importKeys(this.wotsPlus.getWOTSPlusSecretKey(bArr2, oTSHashAddress), bArr);
            XMSSNode randomizeHash = XMSSNodeUtil.randomizeHash(this.wotsPlus, this.authenticationPath.get(calculateTau - 1), this.keep.get(Integer.valueOf(calculateTau - 1)), hashTreeAddress2);
            this.authenticationPath.set(calculateTau, new XMSSNode(randomizeHash.getHeight() + 1, randomizeHash.getValue()));
            this.keep.remove(Integer.valueOf(calculateTau - 1));
            for (int i = 0; i < calculateTau; i++) {
                if (i < this.treeHeight - this.f922k) {
                    this.authenticationPath.set(i, this.treeHashInstances.get(i).getTailNode());
                } else {
                    this.authenticationPath.set(i, this.retain.get(Integer.valueOf(i)).removeFirst());
                }
            }
            int min = Math.min(calculateTau, this.treeHeight - this.f922k);
            for (int i2 = 0; i2 < min; i2++) {
                int i3 = this.index + 1 + (3 * (1 << i2));
                if (i3 < (1 << this.treeHeight)) {
                    this.treeHashInstances.get(i2).initialize(i3);
                }
            }
        }
        for (int i4 = 0; i4 < ((this.treeHeight - this.f922k) >> 1); i4++) {
            BDSTreeHash bDSTreeHashInstanceForUpdate = getBDSTreeHashInstanceForUpdate();
            if (bDSTreeHashInstanceForUpdate != null) {
                bDSTreeHashInstanceForUpdate.update(this.stack, this.wotsPlus, bArr, bArr2, oTSHashAddress);
            }
        }
        this.index++;
    }

    boolean isUsed() {
        return this.used;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void markUsed() {
        this.used = true;
    }

    private BDSTreeHash getBDSTreeHashInstanceForUpdate() {
        BDSTreeHash bDSTreeHash = null;
        for (BDSTreeHash bDSTreeHash2 : this.treeHashInstances) {
            if (!bDSTreeHash2.isFinished() && bDSTreeHash2.isInitialized()) {
                if (bDSTreeHash == null) {
                    bDSTreeHash = bDSTreeHash2;
                } else if (bDSTreeHash2.getHeight() < bDSTreeHash.getHeight()) {
                    bDSTreeHash = bDSTreeHash2;
                } else if (bDSTreeHash2.getHeight() == bDSTreeHash.getHeight() && bDSTreeHash2.getIndexLeaf() < bDSTreeHash.getIndexLeaf()) {
                    bDSTreeHash = bDSTreeHash2;
                }
            }
        }
        return bDSTreeHash;
    }

    private void validate() {
        if (this.authenticationPath == null) {
            throw new IllegalStateException("authenticationPath == null");
        }
        if (this.retain == null) {
            throw new IllegalStateException("retain == null");
        }
        if (this.stack == null) {
            throw new IllegalStateException("stack == null");
        }
        if (this.treeHashInstances == null) {
            throw new IllegalStateException("treeHashInstances == null");
        }
        if (this.keep == null) {
            throw new IllegalStateException("keep == null");
        }
        if (!XMSSUtil.isIndexValid(this.treeHeight, this.index)) {
            throw new IllegalStateException("index in BDS state out of bounds");
        }
    }

    protected int getTreeHeight() {
        return this.treeHeight;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public XMSSNode getRoot() {
        return this.root;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public List<XMSSNode> getAuthenticationPath() {
        ArrayList arrayList = new ArrayList();
        for (XMSSNode xMSSNode : this.authenticationPath) {
            arrayList.add(xMSSNode);
        }
        return arrayList;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int getIndex() {
        return this.index;
    }

    public int getMaxIndex() {
        return this.maxIndex;
    }

    public BDS withWOTSDigest(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return new BDS(this, aSN1ObjectIdentifier);
    }

    public BDS withMaxIndex(int i, ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return new BDS(this, i, aSN1ObjectIdentifier);
    }

    private void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        if (objectInputStream.available() != 0) {
            this.maxIndex = objectInputStream.readInt();
        } else {
            this.maxIndex = (1 << this.treeHeight) - 1;
        }
        if (this.maxIndex > (1 << this.treeHeight) - 1 || this.index > this.maxIndex + 1 || objectInputStream.available() != 0) {
            throw new IOException("inconsistent BDS data detected");
        }
    }

    private void writeObject(ObjectOutputStream objectOutputStream) throws IOException {
        objectOutputStream.defaultWriteObject();
        objectOutputStream.writeInt(this.maxIndex);
    }
}