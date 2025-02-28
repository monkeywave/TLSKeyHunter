package org.bouncycastle.jcajce.provider.keystore.util;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Map;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.jcajce.BCLoadStoreParameter;
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.p019io.Streams;

/* loaded from: classes2.dex */
public class JKSKeyStoreSpi extends KeyStoreSpi {
    private static final String NOT_IMPLEMENTED_MESSAGE = "BC JKS store is read-only and only supports certificate entries";
    private final Hashtable<String, BCJKSTrustedCertEntry> certificateEntries = new Hashtable<>();
    private final JcaJceHelper helper;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public static final class BCJKSTrustedCertEntry {
        final Certificate cert;
        final Date date;

        public BCJKSTrustedCertEntry(Date date, Certificate certificate) {
            this.date = date;
            this.cert = certificate;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public static final class ErasableByteStream extends ByteArrayInputStream {
        public ErasableByteStream(byte[] bArr, int i, int i2) {
            super(bArr, i, i2);
        }

        public void erase() {
            Arrays.fill(this.buf, (byte) 0);
        }
    }

    public JKSKeyStoreSpi(JcaJceHelper jcaJceHelper) {
        this.helper = jcaJceHelper;
    }

    private void addPassword(Digest digest, char[] cArr) throws IOException {
        for (int i = 0; i < cArr.length; i++) {
            digest.update((byte) (cArr[i] >> '\b'));
            digest.update((byte) cArr[i]);
        }
        digest.update(Strings.toByteArray("Mighty Aphrodite"), 0, 16);
    }

    private CertificateFactory createCertFactory(String str) throws CertificateException {
        JcaJceHelper jcaJceHelper = this.helper;
        if (jcaJceHelper != null) {
            try {
                return jcaJceHelper.createCertificateFactory(str);
            } catch (NoSuchProviderException e) {
                throw new CertificateException(e.toString());
            }
        }
        return CertificateFactory.getInstance(str);
    }

    private ErasableByteStream validateStream(InputStream inputStream, char[] cArr) throws IOException {
        Digest digest = DigestFactory.getDigest(McElieceCCA2KeyGenParameterSpec.SHA1);
        byte[] readAll = Streams.readAll(inputStream);
        if (cArr != null) {
            addPassword(digest, cArr);
            digest.update(readAll, 0, readAll.length - digest.getDigestSize());
            int digestSize = digest.getDigestSize();
            byte[] bArr = new byte[digestSize];
            digest.doFinal(bArr, 0);
            byte[] bArr2 = new byte[digestSize];
            System.arraycopy(readAll, readAll.length - digestSize, bArr2, 0, digestSize);
            if (Arrays.constantTimeAreEqual(bArr, bArr2)) {
                return new ErasableByteStream(readAll, 0, readAll.length - digestSize);
            }
            Arrays.fill(readAll, (byte) 0);
            throw new IOException("password incorrect or store tampered with");
        }
        return new ErasableByteStream(readAll, 0, readAll.length - digest.getDigestSize());
    }

    @Override // java.security.KeyStoreSpi
    public Enumeration<String> engineAliases() {
        Enumeration<String> keys;
        synchronized (this.certificateEntries) {
            keys = this.certificateEntries.keys();
        }
        return keys;
    }

    @Override // java.security.KeyStoreSpi
    public boolean engineContainsAlias(String str) {
        boolean containsKey;
        if (str != null) {
            synchronized (this.certificateEntries) {
                containsKey = this.certificateEntries.containsKey(str);
            }
            return containsKey;
        }
        throw new NullPointerException("alias value is null");
    }

    @Override // java.security.KeyStoreSpi
    public void engineDeleteEntry(String str) throws KeyStoreException {
        throw new KeyStoreException(NOT_IMPLEMENTED_MESSAGE);
    }

    @Override // java.security.KeyStoreSpi
    public Certificate engineGetCertificate(String str) {
        synchronized (this.certificateEntries) {
            BCJKSTrustedCertEntry bCJKSTrustedCertEntry = this.certificateEntries.get(str);
            if (bCJKSTrustedCertEntry != null) {
                return bCJKSTrustedCertEntry.cert;
            }
            return null;
        }
    }

    @Override // java.security.KeyStoreSpi
    public String engineGetCertificateAlias(Certificate certificate) {
        synchronized (this.certificateEntries) {
            for (Map.Entry<String, BCJKSTrustedCertEntry> entry : this.certificateEntries.entrySet()) {
                if (entry.getValue().cert.equals(certificate)) {
                    return entry.getKey();
                }
            }
            return null;
        }
    }

    @Override // java.security.KeyStoreSpi
    public Certificate[] engineGetCertificateChain(String str) {
        return null;
    }

    @Override // java.security.KeyStoreSpi
    public Date engineGetCreationDate(String str) {
        synchronized (this.certificateEntries) {
            BCJKSTrustedCertEntry bCJKSTrustedCertEntry = this.certificateEntries.get(str);
            if (bCJKSTrustedCertEntry != null) {
                return bCJKSTrustedCertEntry.date;
            }
            return null;
        }
    }

    @Override // java.security.KeyStoreSpi
    public Key engineGetKey(String str, char[] cArr) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        return null;
    }

    @Override // java.security.KeyStoreSpi
    public boolean engineIsCertificateEntry(String str) {
        boolean containsKey;
        synchronized (this.certificateEntries) {
            containsKey = this.certificateEntries.containsKey(str);
        }
        return containsKey;
    }

    @Override // java.security.KeyStoreSpi
    public boolean engineIsKeyEntry(String str) {
        return false;
    }

    @Override // java.security.KeyStoreSpi
    public void engineLoad(InputStream inputStream, char[] cArr) throws IOException, NoSuchAlgorithmException, CertificateException {
        Hashtable hashtable;
        if (inputStream == null) {
            return;
        }
        ErasableByteStream validateStream = validateStream(inputStream, cArr);
        synchronized (this.certificateEntries) {
            DataInputStream dataInputStream = new DataInputStream(validateStream);
            int readInt = dataInputStream.readInt();
            int readInt2 = dataInputStream.readInt();
            if (readInt == -17957139) {
                CertificateFactory certificateFactory = null;
                int i = 2;
                if (readInt2 == 1) {
                    hashtable = null;
                    certificateFactory = createCertFactory("X.509");
                } else if (readInt2 != 2) {
                    throw new IllegalStateException("unable to discern store version");
                } else {
                    hashtable = new Hashtable();
                }
                int readInt3 = dataInputStream.readInt();
                int i2 = 0;
                while (i2 < readInt3) {
                    int readInt4 = dataInputStream.readInt();
                    if (readInt4 == 1) {
                        throw new IOException(NOT_IMPLEMENTED_MESSAGE);
                    }
                    if (readInt4 != i) {
                        throw new IllegalStateException("unable to discern entry type");
                    }
                    String readUTF = dataInputStream.readUTF();
                    Date date = new Date(dataInputStream.readLong());
                    if (readInt2 == i) {
                        String readUTF2 = dataInputStream.readUTF();
                        if (hashtable.containsKey(readUTF2)) {
                            certificateFactory = (CertificateFactory) hashtable.get(readUTF2);
                        } else {
                            CertificateFactory createCertFactory = createCertFactory(readUTF2);
                            hashtable.put(readUTF2, createCertFactory);
                            certificateFactory = createCertFactory;
                        }
                    }
                    int readInt5 = dataInputStream.readInt();
                    byte[] bArr = new byte[readInt5];
                    dataInputStream.readFully(bArr);
                    ErasableByteStream erasableByteStream = new ErasableByteStream(bArr, 0, readInt5);
                    try {
                        Certificate generateCertificate = certificateFactory.generateCertificate(erasableByteStream);
                        if (erasableByteStream.available() != 0) {
                            throw new IOException("password incorrect or store tampered with");
                        }
                        erasableByteStream.erase();
                        this.certificateEntries.put(readUTF, new BCJKSTrustedCertEntry(date, generateCertificate));
                        i2++;
                        i = 2;
                    } catch (Throwable th) {
                        erasableByteStream.erase();
                        throw th;
                    }
                }
            }
            if (validateStream.available() != 0) {
                throw new IOException("password incorrect or store tampered with");
            }
            validateStream.erase();
        }
    }

    @Override // java.security.KeyStoreSpi
    public void engineLoad(KeyStore.LoadStoreParameter loadStoreParameter) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (loadStoreParameter == null) {
            engineLoad(null, null);
        } else if (!(loadStoreParameter instanceof BCLoadStoreParameter)) {
            throw new IllegalArgumentException("no support for 'param' of type " + loadStoreParameter.getClass().getName());
        } else {
            engineLoad(((BCLoadStoreParameter) loadStoreParameter).getInputStream(), ParameterUtil.extractPassword(loadStoreParameter));
        }
    }

    public boolean engineProbe(InputStream inputStream) throws IOException {
        DataInputStream dataInputStream = inputStream instanceof DataInputStream ? (DataInputStream) inputStream : new DataInputStream(inputStream);
        int readInt = dataInputStream.readInt();
        int readInt2 = dataInputStream.readInt();
        return readInt == -17957139 && (readInt2 == 1 || readInt2 == 2);
    }

    @Override // java.security.KeyStoreSpi
    public void engineSetCertificateEntry(String str, Certificate certificate) throws KeyStoreException {
        throw new KeyStoreException(NOT_IMPLEMENTED_MESSAGE);
    }

    @Override // java.security.KeyStoreSpi
    public void engineSetKeyEntry(String str, Key key, char[] cArr, Certificate[] certificateArr) throws KeyStoreException {
        throw new KeyStoreException(NOT_IMPLEMENTED_MESSAGE);
    }

    @Override // java.security.KeyStoreSpi
    public void engineSetKeyEntry(String str, byte[] bArr, Certificate[] certificateArr) throws KeyStoreException {
        throw new KeyStoreException(NOT_IMPLEMENTED_MESSAGE);
    }

    @Override // java.security.KeyStoreSpi
    public int engineSize() {
        return this.certificateEntries.size();
    }

    @Override // java.security.KeyStoreSpi
    public void engineStore(OutputStream outputStream, char[] cArr) throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new IOException(NOT_IMPLEMENTED_MESSAGE);
    }
}