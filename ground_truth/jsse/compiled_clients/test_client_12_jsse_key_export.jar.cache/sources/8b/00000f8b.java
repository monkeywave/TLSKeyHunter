package org.openjsse.sun.security.provider;

import java.lang.reflect.Field;
import java.nio.ByteOrder;
import java.security.AccessController;
import java.security.PrivilegedAction;
import javassist.bytecode.Opcode;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import sun.misc.Unsafe;
import sun.misc.VM;
import sun.security.action.GetPropertyAction;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/provider/ByteArrayAccess.class */
final class ByteArrayAccess {
    private static final Unsafe unsafe;
    private static final boolean littleEndianUnaligned;
    private static final boolean bigEndian;
    private static final int byteArrayOfs;

    private ByteArrayAccess() {
    }

    static {
        ClassLoader cLoader;
        Object unsafeObj = null;
        try {
            cLoader = ByteArrayAccess.class.getClassLoader();
        } catch (IllegalAccessException | NoSuchFieldException e) {
        }
        if (VM.isSystemDomainLoader(cLoader) || cLoader.getClass().getName().startsWith("sun.misc.Launcher$ExtClassLoader")) {
            Field f = Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            unsafeObj = f.get(null);
            unsafe = (Unsafe) unsafeObj;
            byteArrayOfs = unsafe.arrayBaseOffset(byte[].class);
            boolean scaleOK = unsafe.arrayIndexScale(byte[].class) == 1 && unsafe.arrayIndexScale(int[].class) == 4 && unsafe.arrayIndexScale(long[].class) == 8 && (byteArrayOfs & 3) == 0;
            ByteOrder byteOrder = ByteOrder.nativeOrder();
            littleEndianUnaligned = scaleOK && unaligned() && byteOrder == ByteOrder.LITTLE_ENDIAN;
            bigEndian = scaleOK && byteOrder == ByteOrder.BIG_ENDIAN;
            return;
        }
        throw new SecurityException("Provider must be loaded by ExtClassLoader");
    }

    private static boolean unaligned() {
        String arch = (String) AccessController.doPrivileged((PrivilegedAction<Object>) new GetPropertyAction("os.arch", ""));
        return arch.equals("i386") || arch.equals("x86") || arch.equals("amd64") || arch.equals("x86_64") || arch.equals("ppc64") || arch.equals("ppc64le");
    }

    static void b2iLittle(byte[] in, int inOfs, int[] out, int outOfs, int len) {
        if (inOfs < 0 || in.length - inOfs < len || outOfs < 0 || out.length - outOfs < len / 4) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (littleEndianUnaligned) {
            int inOfs2 = inOfs + byteArrayOfs;
            int len2 = len + inOfs2;
            while (inOfs2 < len2) {
                int i = outOfs;
                outOfs++;
                out[i] = unsafe.getInt(in, inOfs2);
                inOfs2 += 4;
            }
        } else if (bigEndian && (inOfs & 3) == 0) {
            int inOfs3 = inOfs + byteArrayOfs;
            int len3 = len + inOfs3;
            while (inOfs3 < len3) {
                int i2 = outOfs;
                outOfs++;
                out[i2] = Integer.reverseBytes(unsafe.getInt(in, inOfs3));
                inOfs3 += 4;
            }
        } else {
            int len4 = len + inOfs;
            while (inOfs < len4) {
                int i3 = outOfs;
                outOfs++;
                out[i3] = (in[inOfs] & GF2Field.MASK) | ((in[inOfs + 1] & GF2Field.MASK) << 8) | ((in[inOfs + 2] & GF2Field.MASK) << 16) | (in[inOfs + 3] << 24);
                inOfs += 4;
            }
        }
    }

    static void b2iLittle64(byte[] in, int inOfs, int[] out) {
        if (inOfs < 0 || in.length - inOfs < 64 || out.length < 16) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (littleEndianUnaligned) {
            int inOfs2 = inOfs + byteArrayOfs;
            out[0] = unsafe.getInt(in, inOfs2);
            out[1] = unsafe.getInt(in, inOfs2 + 4);
            out[2] = unsafe.getInt(in, inOfs2 + 8);
            out[3] = unsafe.getInt(in, inOfs2 + 12);
            out[4] = unsafe.getInt(in, inOfs2 + 16);
            out[5] = unsafe.getInt(in, inOfs2 + 20);
            out[6] = unsafe.getInt(in, inOfs2 + 24);
            out[7] = unsafe.getInt(in, inOfs2 + 28);
            out[8] = unsafe.getInt(in, inOfs2 + 32);
            out[9] = unsafe.getInt(in, inOfs2 + 36);
            out[10] = unsafe.getInt(in, inOfs2 + 40);
            out[11] = unsafe.getInt(in, inOfs2 + 44);
            out[12] = unsafe.getInt(in, inOfs2 + 48);
            out[13] = unsafe.getInt(in, inOfs2 + 52);
            out[14] = unsafe.getInt(in, inOfs2 + 56);
            out[15] = unsafe.getInt(in, inOfs2 + 60);
        } else if (bigEndian && (inOfs & 3) == 0) {
            int inOfs3 = inOfs + byteArrayOfs;
            out[0] = Integer.reverseBytes(unsafe.getInt(in, inOfs3));
            out[1] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 4));
            out[2] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 8));
            out[3] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 12));
            out[4] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 16));
            out[5] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 20));
            out[6] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 24));
            out[7] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 28));
            out[8] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 32));
            out[9] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 36));
            out[10] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 40));
            out[11] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 44));
            out[12] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 48));
            out[13] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 52));
            out[14] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 56));
            out[15] = Integer.reverseBytes(unsafe.getInt(in, inOfs3 + 60));
        } else {
            b2iLittle(in, inOfs, out, 0, 64);
        }
    }

    static void i2bLittle(int[] in, int inOfs, byte[] out, int outOfs, int len) {
        if (inOfs < 0 || in.length - inOfs < len / 4 || outOfs < 0 || out.length - outOfs < len) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (littleEndianUnaligned) {
            int outOfs2 = outOfs + byteArrayOfs;
            int len2 = len + outOfs2;
            while (outOfs2 < len2) {
                int i = inOfs;
                inOfs++;
                unsafe.putInt(out, outOfs2, in[i]);
                outOfs2 += 4;
            }
        } else if (bigEndian && (outOfs & 3) == 0) {
            int outOfs3 = outOfs + byteArrayOfs;
            int len3 = len + outOfs3;
            while (outOfs3 < len3) {
                int i2 = inOfs;
                inOfs++;
                unsafe.putInt(out, outOfs3, Integer.reverseBytes(in[i2]));
                outOfs3 += 4;
            }
        } else {
            int len4 = len + outOfs;
            while (outOfs < len4) {
                int i3 = inOfs;
                inOfs++;
                int i4 = in[i3];
                int i5 = outOfs;
                int outOfs4 = outOfs + 1;
                out[i5] = (byte) i4;
                int outOfs5 = outOfs4 + 1;
                out[outOfs4] = (byte) (i4 >> 8);
                int outOfs6 = outOfs5 + 1;
                out[outOfs5] = (byte) (i4 >> 16);
                outOfs = outOfs6 + 1;
                out[outOfs6] = (byte) (i4 >> 24);
            }
        }
    }

    static void i2bLittle4(int val, byte[] out, int outOfs) {
        if (outOfs < 0 || out.length - outOfs < 4) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (littleEndianUnaligned) {
            unsafe.putInt(out, byteArrayOfs + outOfs, val);
        } else if (bigEndian && (outOfs & 3) == 0) {
            unsafe.putInt(out, byteArrayOfs + outOfs, Integer.reverseBytes(val));
        } else {
            out[outOfs] = (byte) val;
            out[outOfs + 1] = (byte) (val >> 8);
            out[outOfs + 2] = (byte) (val >> 16);
            out[outOfs + 3] = (byte) (val >> 24);
        }
    }

    static void b2iBig(byte[] in, int inOfs, int[] out, int outOfs, int len) {
        if (inOfs < 0 || in.length - inOfs < len || outOfs < 0 || out.length - outOfs < len / 4) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (littleEndianUnaligned) {
            int inOfs2 = inOfs + byteArrayOfs;
            int len2 = len + inOfs2;
            while (inOfs2 < len2) {
                int i = outOfs;
                outOfs++;
                out[i] = Integer.reverseBytes(unsafe.getInt(in, inOfs2));
                inOfs2 += 4;
            }
        } else if (bigEndian && (inOfs & 3) == 0) {
            int inOfs3 = inOfs + byteArrayOfs;
            int len3 = len + inOfs3;
            while (inOfs3 < len3) {
                int i2 = outOfs;
                outOfs++;
                out[i2] = unsafe.getInt(in, inOfs3);
                inOfs3 += 4;
            }
        } else {
            int len4 = len + inOfs;
            while (inOfs < len4) {
                int i3 = outOfs;
                outOfs++;
                out[i3] = (in[inOfs + 3] & GF2Field.MASK) | ((in[inOfs + 2] & GF2Field.MASK) << 8) | ((in[inOfs + 1] & GF2Field.MASK) << 16) | (in[inOfs] << 24);
                inOfs += 4;
            }
        }
    }

    static void b2iBig64(byte[] in, int inOfs, int[] out) {
        if (inOfs < 0 || in.length - inOfs < 64 || out.length < 16) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (littleEndianUnaligned) {
            int inOfs2 = inOfs + byteArrayOfs;
            out[0] = Integer.reverseBytes(unsafe.getInt(in, inOfs2));
            out[1] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 4));
            out[2] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 8));
            out[3] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 12));
            out[4] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 16));
            out[5] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 20));
            out[6] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 24));
            out[7] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 28));
            out[8] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 32));
            out[9] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 36));
            out[10] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 40));
            out[11] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 44));
            out[12] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 48));
            out[13] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 52));
            out[14] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 56));
            out[15] = Integer.reverseBytes(unsafe.getInt(in, inOfs2 + 60));
        } else if (bigEndian && (inOfs & 3) == 0) {
            int inOfs3 = inOfs + byteArrayOfs;
            out[0] = unsafe.getInt(in, inOfs3);
            out[1] = unsafe.getInt(in, inOfs3 + 4);
            out[2] = unsafe.getInt(in, inOfs3 + 8);
            out[3] = unsafe.getInt(in, inOfs3 + 12);
            out[4] = unsafe.getInt(in, inOfs3 + 16);
            out[5] = unsafe.getInt(in, inOfs3 + 20);
            out[6] = unsafe.getInt(in, inOfs3 + 24);
            out[7] = unsafe.getInt(in, inOfs3 + 28);
            out[8] = unsafe.getInt(in, inOfs3 + 32);
            out[9] = unsafe.getInt(in, inOfs3 + 36);
            out[10] = unsafe.getInt(in, inOfs3 + 40);
            out[11] = unsafe.getInt(in, inOfs3 + 44);
            out[12] = unsafe.getInt(in, inOfs3 + 48);
            out[13] = unsafe.getInt(in, inOfs3 + 52);
            out[14] = unsafe.getInt(in, inOfs3 + 56);
            out[15] = unsafe.getInt(in, inOfs3 + 60);
        } else {
            b2iBig(in, inOfs, out, 0, 64);
        }
    }

    static void i2bBig(int[] in, int inOfs, byte[] out, int outOfs, int len) {
        if (inOfs < 0 || in.length - inOfs < len / 4 || outOfs < 0 || out.length - outOfs < len) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (littleEndianUnaligned) {
            int outOfs2 = outOfs + byteArrayOfs;
            int len2 = len + outOfs2;
            while (outOfs2 < len2) {
                int i = inOfs;
                inOfs++;
                unsafe.putInt(out, outOfs2, Integer.reverseBytes(in[i]));
                outOfs2 += 4;
            }
        } else if (bigEndian && (outOfs & 3) == 0) {
            int outOfs3 = outOfs + byteArrayOfs;
            int len3 = len + outOfs3;
            while (outOfs3 < len3) {
                int i2 = inOfs;
                inOfs++;
                unsafe.putInt(out, outOfs3, in[i2]);
                outOfs3 += 4;
            }
        } else {
            int len4 = len + outOfs;
            while (outOfs < len4) {
                int i3 = inOfs;
                inOfs++;
                int i4 = in[i3];
                int i5 = outOfs;
                int outOfs4 = outOfs + 1;
                out[i5] = (byte) (i4 >> 24);
                int outOfs5 = outOfs4 + 1;
                out[outOfs4] = (byte) (i4 >> 16);
                int outOfs6 = outOfs5 + 1;
                out[outOfs5] = (byte) (i4 >> 8);
                outOfs = outOfs6 + 1;
                out[outOfs6] = (byte) i4;
            }
        }
    }

    static void i2bBig4(int val, byte[] out, int outOfs) {
        if (outOfs < 0 || out.length - outOfs < 4) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (littleEndianUnaligned) {
            unsafe.putInt(out, byteArrayOfs + outOfs, Integer.reverseBytes(val));
        } else if (bigEndian && (outOfs & 3) == 0) {
            unsafe.putInt(out, byteArrayOfs + outOfs, val);
        } else {
            out[outOfs] = (byte) (val >> 24);
            out[outOfs + 1] = (byte) (val >> 16);
            out[outOfs + 2] = (byte) (val >> 8);
            out[outOfs + 3] = (byte) val;
        }
    }

    static void b2lBig(byte[] in, int inOfs, long[] out, int outOfs, int len) {
        if (inOfs < 0 || in.length - inOfs < len || outOfs < 0 || out.length - outOfs < len / 8) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (littleEndianUnaligned) {
            int inOfs2 = inOfs + byteArrayOfs;
            int len2 = len + inOfs2;
            while (inOfs2 < len2) {
                int i = outOfs;
                outOfs++;
                out[i] = Long.reverseBytes(unsafe.getLong(in, inOfs2));
                inOfs2 += 8;
            }
        } else if (bigEndian && (inOfs & 3) == 0) {
            int inOfs3 = inOfs + byteArrayOfs;
            int len3 = len + inOfs3;
            while (inOfs3 < len3) {
                int i2 = outOfs;
                outOfs++;
                out[i2] = (unsafe.getInt(in, inOfs3) << 32) | (unsafe.getInt(in, inOfs3 + 4) & 4294967295L);
                inOfs3 += 8;
            }
        } else {
            int len4 = len + inOfs;
            while (inOfs < len4) {
                int i1 = (in[inOfs + 3] & 255) | ((in[inOfs + 2] & 255) << 8) | ((in[inOfs + 1] & 255) << 16) | (in[inOfs] << 24);
                int inOfs4 = inOfs + 4;
                int i22 = (in[inOfs4 + 3] & 255) | ((in[inOfs4 + 2] & 255) << 8) | ((in[inOfs4 + 1] & 255) << 16) | (in[inOfs4] << 24);
                int i3 = outOfs;
                outOfs++;
                out[i3] = (i1 << 32) | (i22 & 4294967295L);
                inOfs = inOfs4 + 4;
            }
        }
    }

    static void b2lBig128(byte[] in, int inOfs, long[] out) {
        if (inOfs < 0 || in.length - inOfs < 128 || out.length < 16) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (littleEndianUnaligned) {
            int inOfs2 = inOfs + byteArrayOfs;
            out[0] = Long.reverseBytes(unsafe.getLong(in, inOfs2));
            out[1] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + 8));
            out[2] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + 16));
            out[3] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + 24));
            out[4] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + 32));
            out[5] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + 40));
            out[6] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + 48));
            out[7] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + 56));
            out[8] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + 64));
            out[9] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + 72));
            out[10] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + 80));
            out[11] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + 88));
            out[12] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + 96));
            out[13] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + Opcode.IMUL));
            out[14] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + Opcode.IREM));
            out[15] = Long.reverseBytes(unsafe.getLong(in, inOfs2 + Opcode.ISHL));
            return;
        }
        b2lBig(in, inOfs, out, 0, 128);
    }

    static void l2bBig(long[] in, int inOfs, byte[] out, int outOfs, int len) {
        if (inOfs < 0 || in.length - inOfs < len / 8 || outOfs < 0 || out.length - outOfs < len) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (littleEndianUnaligned) {
            int outOfs2 = outOfs + byteArrayOfs;
            int len2 = len + outOfs2;
            while (outOfs2 < len2) {
                int i = inOfs;
                inOfs++;
                unsafe.putLong(out, outOfs2, Long.reverseBytes(in[i]));
                outOfs2 += 8;
            }
            return;
        }
        int len3 = len + outOfs;
        while (outOfs < len3) {
            int i2 = inOfs;
            inOfs++;
            long i3 = in[i2];
            int i4 = outOfs;
            int outOfs3 = outOfs + 1;
            out[i4] = (byte) (i3 >> 56);
            int outOfs4 = outOfs3 + 1;
            out[outOfs3] = (byte) (i3 >> 48);
            int outOfs5 = outOfs4 + 1;
            out[outOfs4] = (byte) (i3 >> 40);
            int outOfs6 = outOfs5 + 1;
            out[outOfs5] = (byte) (i3 >> 32);
            int outOfs7 = outOfs6 + 1;
            out[outOfs6] = (byte) (i3 >> 24);
            int outOfs8 = outOfs7 + 1;
            out[outOfs7] = (byte) (i3 >> 16);
            int outOfs9 = outOfs8 + 1;
            out[outOfs8] = (byte) (i3 >> 8);
            outOfs = outOfs9 + 1;
            out[outOfs9] = (byte) i3;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void b2lLittle(byte[] in, int inOfs, long[] out, int outOfs, int len) {
        if (inOfs < 0 || in.length - inOfs < len || outOfs < 0 || out.length - outOfs < len / 8) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (littleEndianUnaligned) {
            int inOfs2 = inOfs + byteArrayOfs;
            int len2 = len + inOfs2;
            while (inOfs2 < len2) {
                int i = outOfs;
                outOfs++;
                out[i] = unsafe.getLong(in, inOfs2);
                inOfs2 += 8;
            }
            return;
        }
        int len3 = len + inOfs;
        while (inOfs < len3) {
            int i2 = outOfs;
            outOfs++;
            out[i2] = (in[inOfs] & 255) | ((in[inOfs + 1] & 255) << 8) | ((in[inOfs + 2] & 255) << 16) | ((in[inOfs + 3] & 255) << 24) | ((in[inOfs + 4] & 255) << 32) | ((in[inOfs + 5] & 255) << 40) | ((in[inOfs + 6] & 255) << 48) | ((in[inOfs + 7] & 255) << 56);
            inOfs += 8;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void l2bLittle(long[] in, int inOfs, byte[] out, int outOfs, int len) {
        if (inOfs < 0 || in.length - inOfs < len / 8 || outOfs < 0 || out.length - outOfs < len) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (littleEndianUnaligned) {
            int outOfs2 = outOfs + byteArrayOfs;
            int len2 = len + outOfs2;
            while (outOfs2 < len2) {
                int i = inOfs;
                inOfs++;
                unsafe.putLong(out, outOfs2, in[i]);
                outOfs2 += 8;
            }
            return;
        }
        int len3 = len + outOfs;
        while (outOfs < len3) {
            int i2 = inOfs;
            inOfs++;
            long i3 = in[i2];
            int i4 = outOfs;
            int outOfs3 = outOfs + 1;
            out[i4] = (byte) i3;
            int outOfs4 = outOfs3 + 1;
            out[outOfs3] = (byte) (i3 >> 8);
            int outOfs5 = outOfs4 + 1;
            out[outOfs4] = (byte) (i3 >> 16);
            int outOfs6 = outOfs5 + 1;
            out[outOfs5] = (byte) (i3 >> 24);
            int outOfs7 = outOfs6 + 1;
            out[outOfs6] = (byte) (i3 >> 32);
            int outOfs8 = outOfs7 + 1;
            out[outOfs7] = (byte) (i3 >> 40);
            int outOfs9 = outOfs8 + 1;
            out[outOfs8] = (byte) (i3 >> 48);
            outOfs = outOfs9 + 1;
            out[outOfs9] = (byte) (i3 >> 56);
        }
    }
}