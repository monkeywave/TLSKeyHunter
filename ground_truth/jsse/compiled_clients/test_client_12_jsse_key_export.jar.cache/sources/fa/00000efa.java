package org.bouncycastle.util.encoders;

import javassist.bytecode.Opcode;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/encoders/UTF8.class */
public class UTF8 {
    private static final byte C_ILL = 0;
    private static final byte C_CR1 = 1;
    private static final byte C_CR2 = 2;
    private static final byte C_CR3 = 3;
    private static final byte C_L2A = 4;
    private static final byte C_L3A = 5;
    private static final byte C_L3B = 6;
    private static final byte C_L3C = 7;
    private static final byte C_L4A = 8;
    private static final byte C_L4B = 9;
    private static final byte C_L4C = 10;
    private static final byte S_ERR = -2;
    private static final byte S_END = -1;
    private static final byte S_CS1 = 0;
    private static final byte S_CS2 = 16;
    private static final byte S_CS3 = 32;
    private static final byte S_P3A = 48;
    private static final byte S_P3B = 64;
    private static final byte S_P4A = 80;
    private static final byte S_P4B = 96;
    private static final short[] firstUnitTable = new short[128];
    private static final byte[] transitionTable = new byte[Opcode.IREM];

    private static void fill(byte[] bArr, int i, int i2, byte b) {
        for (int i3 = i; i3 <= i2; i3++) {
            bArr[i3] = b;
        }
    }

    public static int transcodeToUTF16(byte[] bArr, char[] cArr) {
        int i = 0;
        int i2 = 0;
        while (i < bArr.length) {
            int i3 = i;
            i++;
            byte b = bArr[i3];
            if (b < 0) {
                short s = firstUnitTable[b & Byte.MAX_VALUE];
                int i4 = s >>> 8;
                byte b2 = (byte) s;
                while (true) {
                    byte b3 = b2;
                    if (b3 >= 0) {
                        if (i >= bArr.length) {
                            return S_END;
                        }
                        int i5 = i;
                        i++;
                        byte b4 = bArr[i5];
                        i4 = (i4 << 6) | (b4 & 63);
                        b2 = transitionTable[b3 + ((b4 & 255) >>> 4)];
                    } else if (b3 == S_ERR) {
                        return S_END;
                    } else {
                        if (i4 <= 65535) {
                            if (i2 >= cArr.length) {
                                return S_END;
                            }
                            int i6 = i2;
                            i2++;
                            cArr[i6] = (char) i4;
                        } else if (i2 >= cArr.length - 1) {
                            return S_END;
                        } else {
                            int i7 = i2;
                            int i8 = i2 + 1;
                            cArr[i7] = (char) (55232 + (i4 >>> 10));
                            i2 = i8 + 1;
                            cArr[i8] = (char) (56320 | (i4 & 1023));
                        }
                    }
                }
            } else if (i2 >= cArr.length) {
                return S_END;
            } else {
                int i9 = i2;
                i2++;
                cArr[i9] = (char) b;
            }
        }
        return i2;
    }

    static {
        byte[] bArr = new byte[128];
        fill(bArr, 0, 15, (byte) 1);
        fill(bArr, 16, 31, (byte) 2);
        fill(bArr, 32, 63, (byte) 3);
        fill(bArr, 64, 65, (byte) 0);
        fill(bArr, 66, 95, (byte) 4);
        fill(bArr, 96, 96, (byte) 5);
        fill(bArr, 97, Opcode.IDIV, (byte) 6);
        fill(bArr, Opcode.LDIV, Opcode.LDIV, (byte) 7);
        fill(bArr, Opcode.FDIV, Opcode.DDIV, (byte) 6);
        fill(bArr, Opcode.IREM, Opcode.IREM, (byte) 8);
        fill(bArr, Opcode.LREM, Opcode.DREM, (byte) 9);
        fill(bArr, Opcode.INEG, Opcode.INEG, (byte) 10);
        fill(bArr, Opcode.LNEG, Opcode.LAND, (byte) 0);
        fill(transitionTable, 0, transitionTable.length - 1, (byte) -2);
        fill(transitionTable, 8, 11, (byte) -1);
        fill(transitionTable, 24, 27, (byte) 0);
        fill(transitionTable, 40, 43, (byte) 16);
        fill(transitionTable, 58, 59, (byte) 0);
        fill(transitionTable, 72, 73, (byte) 0);
        fill(transitionTable, 89, 91, (byte) 16);
        fill(transitionTable, Opcode.IMUL, Opcode.IMUL, (byte) 16);
        byte[] bArr2 = {0, 0, 0, 0, 31, 15, 15, 15, 7, 7, 7};
        byte[] bArr3 = {S_ERR, S_ERR, S_ERR, S_ERR, 0, 48, 16, 64, 80, 32, 96};
        for (int i = 0; i < 128; i++) {
            byte b = bArr[i];
            firstUnitTable[i] = (short) (((i & bArr2[b]) << 8) | bArr3[b]);
        }
    }
}