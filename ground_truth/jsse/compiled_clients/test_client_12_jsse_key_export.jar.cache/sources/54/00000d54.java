package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.util.p012io.Streams;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/HSSPrivateKeyParameters.class */
public class HSSPrivateKeyParameters extends LMSKeyParameters implements LMSContextBasedSigner {

    /* renamed from: l */
    private final int f826l;
    private final boolean isShard;
    private List<LMSPrivateKeyParameters> keys;
    private List<LMSSignature> sig;
    private final long indexLimit;
    private long index;
    private HSSPublicKeyParameters publicKey;

    public HSSPrivateKeyParameters(int i, List<LMSPrivateKeyParameters> list, List<LMSSignature> list2, long j, long j2) {
        super(true);
        this.index = 0L;
        this.f826l = i;
        this.keys = Collections.unmodifiableList(list);
        this.sig = Collections.unmodifiableList(list2);
        this.index = j;
        this.indexLimit = j2;
        this.isShard = false;
        resetKeyToIndex();
    }

    private HSSPrivateKeyParameters(int i, List<LMSPrivateKeyParameters> list, List<LMSSignature> list2, long j, long j2, boolean z) {
        super(true);
        this.index = 0L;
        this.f826l = i;
        this.keys = Collections.unmodifiableList(list);
        this.sig = Collections.unmodifiableList(list2);
        this.index = j;
        this.indexLimit = j2;
        this.isShard = z;
    }

    public static HSSPrivateKeyParameters getInstance(byte[] bArr, byte[] bArr2) throws IOException {
        HSSPrivateKeyParameters hSSPrivateKeyParameters = getInstance(bArr);
        hSSPrivateKeyParameters.publicKey = HSSPublicKeyParameters.getInstance(bArr2);
        return hSSPrivateKeyParameters;
    }

    public static HSSPrivateKeyParameters getInstance(Object obj) throws IOException {
        if (obj instanceof HSSPrivateKeyParameters) {
            return (HSSPrivateKeyParameters) obj;
        }
        if (obj instanceof DataInputStream) {
            if (((DataInputStream) obj).readInt() != 0) {
                throw new IllegalStateException("unknown version for hss private key");
            } else {
                int readInt = ((DataInputStream) obj).readInt();
                long readLong = ((DataInputStream) obj).readLong();
                long readLong2 = ((DataInputStream) obj).readLong();
                boolean readBoolean = ((DataInputStream) obj).readBoolean();
                ArrayList arrayList = new ArrayList();
                ArrayList arrayList2 = new ArrayList();
                for (int i = 0; i < readInt; i++) {
                    arrayList.add(LMSPrivateKeyParameters.getInstance(obj));
                }
                for (int i2 = 0; i2 < readInt - 1; i2++) {
                    arrayList2.add(LMSSignature.getInstance(obj));
                }
                return new HSSPrivateKeyParameters(readInt, arrayList, arrayList2, readLong, readLong2, readBoolean);
            }
        }
        if (!(obj instanceof byte[])) {
            if (obj instanceof InputStream) {
                return getInstance(Streams.readAll((InputStream) obj));
            }
            throw new IllegalArgumentException("cannot parse " + obj);
        }
        DataInputStream dataInputStream = null;
        try {
            dataInputStream = new DataInputStream(new ByteArrayInputStream((byte[]) obj));
            HSSPrivateKeyParameters hSSPrivateKeyParameters = getInstance(dataInputStream);
            if (dataInputStream != null) {
                dataInputStream.close();
            }
            return hSSPrivateKeyParameters;
        } catch (Throwable th) {
            if (dataInputStream != null) {
                dataInputStream.close();
            }
            throw th;
        }
    }

    public int getL() {
        return this.f826l;
    }

    public synchronized long getIndex() {
        return this.index;
    }

    public synchronized LMSParameters[] getLMSParameters() {
        int size = this.keys.size();
        LMSParameters[] lMSParametersArr = new LMSParameters[size];
        for (int i = 0; i < size; i++) {
            LMSPrivateKeyParameters lMSPrivateKeyParameters = this.keys.get(i);
            lMSParametersArr[i] = new LMSParameters(lMSPrivateKeyParameters.getSigParameters(), lMSPrivateKeyParameters.getOtsParameters());
        }
        return lMSParametersArr;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized void incIndex() {
        this.index++;
    }

    private static HSSPrivateKeyParameters makeCopy(HSSPrivateKeyParameters hSSPrivateKeyParameters) {
        try {
            return getInstance(hSSPrivateKeyParameters.getEncoded());
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    protected void updateHierarchy(LMSPrivateKeyParameters[] lMSPrivateKeyParametersArr, LMSSignature[] lMSSignatureArr) {
        synchronized (this) {
            this.keys = Collections.unmodifiableList(Arrays.asList(lMSPrivateKeyParametersArr));
            this.sig = Collections.unmodifiableList(Arrays.asList(lMSSignatureArr));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isShard() {
        return this.isShard;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public long getIndexLimit() {
        return this.indexLimit;
    }

    @Override // org.bouncycastle.pqc.crypto.lms.LMSContextBasedSigner
    public long getUsagesRemaining() {
        return this.indexLimit - this.index;
    }

    LMSPrivateKeyParameters getRootKey() {
        return this.keys.get(0);
    }

    public HSSPrivateKeyParameters extractKeyShard(int i) {
        HSSPrivateKeyParameters makeCopy;
        synchronized (this) {
            if (getUsagesRemaining() < i) {
                throw new IllegalArgumentException("usageCount exceeds usages remaining in current leaf");
            }
            long j = this.index + i;
            long j2 = this.index;
            this.index += i;
            makeCopy = makeCopy(new HSSPrivateKeyParameters(this.f826l, new ArrayList(getKeys()), new ArrayList(getSig()), j2, j, true));
            resetKeyToIndex();
        }
        return makeCopy;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized List<LMSPrivateKeyParameters> getKeys() {
        return this.keys;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized List<LMSSignature> getSig() {
        return this.sig;
    }

    void resetKeyToIndex() {
        List<LMSPrivateKeyParameters> keys = getKeys();
        long[] jArr = new long[keys.size()];
        long index = getIndex();
        for (int size = keys.size() - 1; size >= 0; size--) {
            LMSigParameters sigParameters = keys.get(size).getSigParameters();
            jArr[size] = index & ((1 << sigParameters.getH()) - 1);
            index >>>= sigParameters.getH();
        }
        boolean z = false;
        LMSPrivateKeyParameters[] lMSPrivateKeyParametersArr = (LMSPrivateKeyParameters[]) keys.toArray(new LMSPrivateKeyParameters[keys.size()]);
        LMSSignature[] lMSSignatureArr = (LMSSignature[]) this.sig.toArray(new LMSSignature[this.sig.size()]);
        LMSPrivateKeyParameters rootKey = getRootKey();
        if (lMSPrivateKeyParametersArr[0].getIndex() - 1 != jArr[0]) {
            lMSPrivateKeyParametersArr[0] = LMS.generateKeys(rootKey.getSigParameters(), rootKey.getOtsParameters(), (int) jArr[0], rootKey.getI(), rootKey.getMasterSecret());
            z = true;
        }
        int i = 1;
        while (i < jArr.length) {
            LMSPrivateKeyParameters lMSPrivateKeyParameters = lMSPrivateKeyParametersArr[i - 1];
            byte[] bArr = new byte[16];
            byte[] bArr2 = new byte[32];
            SeedDerive seedDerive = new SeedDerive(lMSPrivateKeyParameters.getI(), lMSPrivateKeyParameters.getMasterSecret(), DigestUtil.getDigest(lMSPrivateKeyParameters.getOtsParameters().getDigestOID()));
            seedDerive.setQ((int) jArr[i - 1]);
            seedDerive.setJ(-2);
            seedDerive.deriveSeed(bArr2, true);
            byte[] bArr3 = new byte[32];
            seedDerive.deriveSeed(bArr3, false);
            System.arraycopy(bArr3, 0, bArr, 0, bArr.length);
            boolean z2 = i < jArr.length - 1 ? jArr[i] == ((long) (lMSPrivateKeyParametersArr[i].getIndex() - 1)) : jArr[i] == ((long) lMSPrivateKeyParametersArr[i].getIndex());
            if (!(org.bouncycastle.util.Arrays.areEqual(bArr, lMSPrivateKeyParametersArr[i].getI()) && org.bouncycastle.util.Arrays.areEqual(bArr2, lMSPrivateKeyParametersArr[i].getMasterSecret()))) {
                lMSPrivateKeyParametersArr[i] = LMS.generateKeys(keys.get(i).getSigParameters(), keys.get(i).getOtsParameters(), (int) jArr[i], bArr, bArr2);
                lMSSignatureArr[i - 1] = LMS.generateSign(lMSPrivateKeyParametersArr[i - 1], lMSPrivateKeyParametersArr[i].getPublicKey().toByteArray());
                z = true;
            } else if (!z2) {
                lMSPrivateKeyParametersArr[i] = LMS.generateKeys(keys.get(i).getSigParameters(), keys.get(i).getOtsParameters(), (int) jArr[i], bArr, bArr2);
                z = true;
            }
            i++;
        }
        if (z) {
            updateHierarchy(lMSPrivateKeyParametersArr, lMSSignatureArr);
        }
    }

    public synchronized HSSPublicKeyParameters getPublicKey() {
        return new HSSPublicKeyParameters(this.f826l, getRootKey().getPublicKey());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void replaceConsumedKey(int i) {
        SeedDerive derivationFunction = this.keys.get(i - 1).getCurrentOTSKey().getDerivationFunction();
        derivationFunction.setJ(-2);
        byte[] bArr = new byte[32];
        derivationFunction.deriveSeed(bArr, true);
        byte[] bArr2 = new byte[32];
        derivationFunction.deriveSeed(bArr2, false);
        byte[] bArr3 = new byte[16];
        System.arraycopy(bArr2, 0, bArr3, 0, bArr3.length);
        ArrayList arrayList = new ArrayList(this.keys);
        LMSPrivateKeyParameters lMSPrivateKeyParameters = this.keys.get(i);
        arrayList.set(i, LMS.generateKeys(lMSPrivateKeyParameters.getSigParameters(), lMSPrivateKeyParameters.getOtsParameters(), 0, bArr3, bArr));
        ArrayList arrayList2 = new ArrayList(this.sig);
        arrayList2.set(i - 1, LMS.generateSign((LMSPrivateKeyParameters) arrayList.get(i - 1), ((LMSPrivateKeyParameters) arrayList.get(i)).getPublicKey().toByteArray()));
        this.keys = Collections.unmodifiableList(arrayList);
        this.sig = Collections.unmodifiableList(arrayList2);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        HSSPrivateKeyParameters hSSPrivateKeyParameters = (HSSPrivateKeyParameters) obj;
        if (this.f826l == hSSPrivateKeyParameters.f826l && this.isShard == hSSPrivateKeyParameters.isShard && this.indexLimit == hSSPrivateKeyParameters.indexLimit && this.index == hSSPrivateKeyParameters.index && this.keys.equals(hSSPrivateKeyParameters.keys)) {
            return this.sig.equals(hSSPrivateKeyParameters.sig);
        }
        return false;
    }

    @Override // org.bouncycastle.pqc.crypto.lms.LMSKeyParameters, org.bouncycastle.util.Encodable
    public synchronized byte[] getEncoded() throws IOException {
        Composer bool = Composer.compose().u32str(0).u32str(this.f826l).u64str(this.index).u64str(this.indexLimit).bool(this.isShard);
        for (LMSPrivateKeyParameters lMSPrivateKeyParameters : this.keys) {
            bool.bytes(lMSPrivateKeyParameters);
        }
        for (LMSSignature lMSSignature : this.sig) {
            bool.bytes(lMSSignature);
        }
        return bool.build();
    }

    public int hashCode() {
        return (31 * ((31 * ((31 * ((31 * ((31 * this.f826l) + (this.isShard ? 1 : 0))) + this.keys.hashCode())) + this.sig.hashCode())) + ((int) (this.indexLimit ^ (this.indexLimit >>> 32))))) + ((int) (this.index ^ (this.index >>> 32)));
    }

    protected Object clone() throws CloneNotSupportedException {
        return makeCopy(this);
    }

    @Override // org.bouncycastle.pqc.crypto.lms.LMSContextBasedSigner
    public LMSContext generateLMSContext() {
        LMSPrivateKeyParameters lMSPrivateKeyParameters;
        LMSSignedPubKey[] lMSSignedPubKeyArr;
        int l = getL();
        synchronized (this) {
            HSS.rangeTestKeys(this);
            List<LMSPrivateKeyParameters> keys = getKeys();
            List<LMSSignature> sig = getSig();
            lMSPrivateKeyParameters = getKeys().get(l - 1);
            lMSSignedPubKeyArr = new LMSSignedPubKey[l - 1];
            for (int i = 0; i < l - 1; i++) {
                lMSSignedPubKeyArr[i] = new LMSSignedPubKey(sig.get(i), keys.get(i + 1).getPublicKey());
            }
            incIndex();
        }
        return lMSPrivateKeyParameters.generateLMSContext().withSignedPublicKeys(lMSSignedPubKeyArr);
    }

    @Override // org.bouncycastle.pqc.crypto.lms.LMSContextBasedSigner
    public byte[] generateSignature(LMSContext lMSContext) {
        try {
            return HSS.generateSignature(getL(), lMSContext).getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("unable to encode signature: " + e.getMessage(), e);
        }
    }
}