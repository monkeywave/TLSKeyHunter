package org.bouncycastle.pqc.crypto.xmss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.util.HashSet;
import java.util.Set;
import kotlin.UByte;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: classes2.dex */
public class XMSSUtil {

    /* loaded from: classes2.dex */
    private static class CheckingStream extends ObjectInputStream {
        private static final Set components;
        private boolean found;
        private final Class mainClass;

        static {
            HashSet hashSet = new HashSet();
            components = hashSet;
            hashSet.add("java.util.TreeMap");
            hashSet.add("java.lang.Integer");
            hashSet.add("java.lang.Number");
            hashSet.add("org.bouncycastle.pqc.crypto.xmss.BDS");
            hashSet.add("java.util.ArrayList");
            hashSet.add("org.bouncycastle.pqc.crypto.xmss.XMSSNode");
            hashSet.add("[B");
            hashSet.add("java.util.LinkedList");
            hashSet.add("java.util.Stack");
            hashSet.add("java.util.Vector");
            hashSet.add("[Ljava.lang.Object;");
            hashSet.add("org.bouncycastle.pqc.crypto.xmss.BDSTreeHash");
        }

        CheckingStream(Class cls, InputStream inputStream) throws IOException {
            super(inputStream);
            this.found = false;
            this.mainClass = cls;
        }

        @Override // java.io.ObjectInputStream
        protected Class<?> resolveClass(ObjectStreamClass objectStreamClass) throws IOException, ClassNotFoundException {
            if (this.found) {
                if (!components.contains(objectStreamClass.getName())) {
                    throw new InvalidClassException("unexpected class: ", objectStreamClass.getName());
                }
            } else if (!objectStreamClass.getName().equals(this.mainClass.getName())) {
                throw new InvalidClassException("unexpected class: ", objectStreamClass.getName());
            } else {
                this.found = true;
            }
            return super.resolveClass(objectStreamClass);
        }
    }

    public static boolean areEqual(byte[][] bArr, byte[][] bArr2) {
        if (hasNullPointer(bArr) || hasNullPointer(bArr2)) {
            throw new NullPointerException("a or b == null");
        }
        for (int i = 0; i < bArr.length; i++) {
            if (!Arrays.areEqual(bArr[i], bArr2[i])) {
                return false;
            }
        }
        return true;
    }

    public static long bytesToXBigEndian(byte[] bArr, int i, int i2) {
        if (bArr != null) {
            long j = 0;
            for (int i3 = i; i3 < i + i2; i3++) {
                j = (j << 8) | (bArr[i3] & UByte.MAX_VALUE);
            }
            return j;
        }
        throw new NullPointerException("in == null");
    }

    public static int calculateTau(int i, int i2) {
        for (int i3 = 0; i3 < i2; i3++) {
            if (((i >> i3) & 1) == 0) {
                return i3;
            }
        }
        return 0;
    }

    public static byte[] cloneArray(byte[] bArr) {
        if (bArr != null) {
            byte[] bArr2 = new byte[bArr.length];
            System.arraycopy(bArr, 0, bArr2, 0, bArr.length);
            return bArr2;
        }
        throw new NullPointerException("in == null");
    }

    public static byte[][] cloneArray(byte[][] bArr) {
        if (hasNullPointer(bArr)) {
            throw new NullPointerException("in has null pointers");
        }
        byte[][] bArr2 = new byte[bArr.length];
        for (int i = 0; i < bArr.length; i++) {
            byte[] bArr3 = new byte[bArr[i].length];
            bArr2[i] = bArr3;
            byte[] bArr4 = bArr[i];
            System.arraycopy(bArr4, 0, bArr3, 0, bArr4.length);
        }
        return bArr2;
    }

    public static void copyBytesAtOffset(byte[] bArr, byte[] bArr2, int i) {
        if (bArr == null) {
            throw new NullPointerException("dst == null");
        }
        if (bArr2 == null) {
            throw new NullPointerException("src == null");
        }
        if (i < 0) {
            throw new IllegalArgumentException("offset hast to be >= 0");
        }
        if (bArr2.length + i > bArr.length) {
            throw new IllegalArgumentException("src length + offset must not be greater than size of destination");
        }
        for (int i2 = 0; i2 < bArr2.length; i2++) {
            bArr[i + i2] = bArr2[i2];
        }
    }

    public static Object deserialize(byte[] bArr, Class cls) throws IOException, ClassNotFoundException {
        CheckingStream checkingStream = new CheckingStream(cls, new ByteArrayInputStream(bArr));
        Object readObject = checkingStream.readObject();
        if (checkingStream.available() == 0) {
            if (cls.isInstance(readObject)) {
                return readObject;
            }
            throw new IOException("unexpected class found in ObjectInputStream");
        }
        throw new IOException("unexpected data found at end of ObjectInputStream");
    }

    public static void dumpByteArray(byte[][] bArr) {
        if (hasNullPointer(bArr)) {
            throw new NullPointerException("x has null pointers");
        }
        for (byte[] bArr2 : bArr) {
            System.out.println(Hex.toHexString(bArr2));
        }
    }

    public static byte[] extractBytesAtOffset(byte[] bArr, int i, int i2) {
        if (bArr != null) {
            if (i >= 0) {
                if (i2 >= 0) {
                    if (i + i2 <= bArr.length) {
                        byte[] bArr2 = new byte[i2];
                        for (int i3 = 0; i3 < i2; i3++) {
                            bArr2[i3] = bArr[i + i3];
                        }
                        return bArr2;
                    }
                    throw new IllegalArgumentException("offset + length must not be greater then size of source array");
                }
                throw new IllegalArgumentException("length hast to be >= 0");
            }
            throw new IllegalArgumentException("offset hast to be >= 0");
        }
        throw new NullPointerException("src == null");
    }

    public static int getDigestSize(Digest digest) {
        if (digest != null) {
            String algorithmName = digest.getAlgorithmName();
            if (algorithmName.equals("SHAKE128")) {
                return 32;
            }
            if (algorithmName.equals("SHAKE256")) {
                return 64;
            }
            return digest.getDigestSize();
        }
        throw new NullPointerException("digest == null");
    }

    public static int getLeafIndex(long j, int i) {
        return (int) (j & ((1 << i) - 1));
    }

    public static long getTreeIndex(long j, int i) {
        return j >> i;
    }

    public static boolean hasNullPointer(byte[][] bArr) {
        if (bArr == null) {
            return true;
        }
        for (byte[] bArr2 : bArr) {
            if (bArr2 == null) {
                return true;
            }
        }
        return false;
    }

    public static boolean isIndexValid(int i, long j) {
        if (j >= 0) {
            return j < (1 << i);
        }
        throw new IllegalStateException("index must not be negative");
    }

    public static boolean isNewAuthenticationPathNeeded(long j, int i, int i2) {
        return j != 0 && (j + 1) % ((long) Math.pow((double) (1 << i), (double) i2)) == 0;
    }

    public static boolean isNewBDSInitNeeded(long j, int i, int i2) {
        return j != 0 && j % ((long) Math.pow((double) (1 << i), (double) (i2 + 1))) == 0;
    }

    public static int log2(int i) {
        int i2 = 0;
        while (true) {
            i >>= 1;
            if (i == 0) {
                return i2;
            }
            i2++;
        }
    }

    public static void longToBigEndian(long j, byte[] bArr, int i) {
        if (bArr == null) {
            throw new NullPointerException("in == null");
        }
        if (bArr.length - i < 8) {
            throw new IllegalArgumentException("not enough space in array");
        }
        bArr[i] = (byte) ((j >> 56) & 255);
        bArr[i + 1] = (byte) ((j >> 48) & 255);
        bArr[i + 2] = (byte) ((j >> 40) & 255);
        bArr[i + 3] = (byte) ((j >> 32) & 255);
        bArr[i + 4] = (byte) ((j >> 24) & 255);
        bArr[i + 5] = (byte) ((j >> 16) & 255);
        bArr[i + 6] = (byte) ((j >> 8) & 255);
        bArr[i + 7] = (byte) (j & 255);
    }

    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        objectOutputStream.flush();
        return byteArrayOutputStream.toByteArray();
    }

    public static byte[] toBytesBigEndian(long j, int i) {
        byte[] bArr = new byte[i];
        for (int i2 = i - 1; i2 >= 0; i2--) {
            bArr[i2] = (byte) j;
            j >>>= 8;
        }
        return bArr;
    }
}