package org.bouncycastle.pqc.crypto.rainbow;

import java.lang.reflect.Array;

/* loaded from: classes2.dex */
class ComputeInField {
    private void gaussElim(short[][] sArr) {
        int i = 0;
        while (i < sArr.length) {
            int i2 = i + 1;
            for (int i3 = i2; i3 < sArr.length; i3++) {
                if (sArr[i][i] == 0) {
                    for (int i4 = i; i4 < sArr[0].length; i4++) {
                        short[] sArr2 = sArr[i];
                        sArr2[i4] = GF2Field.addElem(sArr2[i4], sArr[i3][i4]);
                    }
                }
            }
            short invElem = GF2Field.invElem(sArr[i][i]);
            if (invElem == 0) {
                throw new RuntimeException("The matrix is not invertible");
            }
            sArr[i] = multVect(invElem, sArr[i]);
            for (int i5 = 0; i5 < sArr.length; i5++) {
                if (i != i5) {
                    short s = sArr[i5][i];
                    for (int i6 = i; i6 < sArr[0].length; i6++) {
                        short multElem = GF2Field.multElem(sArr[i][i6], s);
                        short[] sArr3 = sArr[i5];
                        sArr3[i6] = GF2Field.addElem(sArr3[i6], multElem);
                    }
                }
            }
            i = i2;
        }
    }

    public short[][] addMatrix(short[][] sArr, short[][] sArr2) {
        if (sArr.length == sArr2.length) {
            short[] sArr3 = sArr[0];
            if (sArr3.length == sArr2[0].length) {
                short[][] sArr4 = (short[][]) Array.newInstance(Short.TYPE, sArr.length, sArr3.length);
                for (int i = 0; i < sArr.length; i++) {
                    for (int i2 = 0; i2 < sArr[0].length; i2++) {
                        sArr4[i][i2] = GF2Field.addElem(sArr[i][i2], sArr2[i][i2]);
                    }
                }
                return sArr4;
            }
        }
        throw new RuntimeException("Addition is not possible!");
    }

    public short[][] addMatrixTranspose(short[][] sArr) {
        if (sArr.length == sArr[0].length) {
            return addMatrix(sArr, transpose(sArr));
        }
        throw new RuntimeException("Addition is not possible!");
    }

    public short[] addVect(short[] sArr, short[] sArr2) {
        if (sArr.length == sArr2.length) {
            int length = sArr.length;
            short[] sArr3 = new short[length];
            for (int i = 0; i < length; i++) {
                sArr3[i] = GF2Field.addElem(sArr[i], sArr2[i]);
            }
            return sArr3;
        }
        throw new RuntimeException("Addition is not possible! vector1.length: " + sArr.length + " vector2.length: " + sArr2.length);
    }

    public short[][] inverse(short[][] sArr) {
        if (sArr.length == sArr[0].length) {
            try {
                short[][] sArr2 = (short[][]) Array.newInstance(Short.TYPE, sArr.length, sArr.length * 2);
                for (int i = 0; i < sArr.length; i++) {
                    System.arraycopy(sArr[i], 0, sArr2[i], 0, sArr.length);
                    for (int length = sArr.length; length < sArr.length * 2; length++) {
                        sArr2[i][length] = 0;
                    }
                    sArr2[i][sArr2.length + i] = 1;
                }
                gaussElim(sArr2);
                short[][] sArr3 = (short[][]) Array.newInstance(Short.TYPE, sArr2.length, sArr2.length);
                for (int i2 = 0; i2 < sArr2.length; i2++) {
                    for (int length2 = sArr2.length; length2 < sArr2.length * 2; length2++) {
                        sArr3[i2][length2 - sArr2.length] = sArr2[i2][length2];
                    }
                }
                return sArr3;
            } catch (RuntimeException unused) {
                return null;
            }
        }
        throw new RuntimeException("The matrix is not invertible. Please choose another one!");
    }

    public short[][] multMatrix(short s, short[][] sArr) {
        short[][] sArr2 = (short[][]) Array.newInstance(Short.TYPE, sArr.length, sArr[0].length);
        for (int i = 0; i < sArr.length; i++) {
            for (int i2 = 0; i2 < sArr[0].length; i2++) {
                sArr2[i][i2] = GF2Field.multElem(s, sArr[i][i2]);
            }
        }
        return sArr2;
    }

    public short[] multVect(short s, short[] sArr) {
        int length = sArr.length;
        short[] sArr2 = new short[length];
        for (int i = 0; i < length; i++) {
            sArr2[i] = GF2Field.multElem(s, sArr[i]);
        }
        return sArr2;
    }

    public short[][] multVects(short[] sArr, short[] sArr2) {
        if (sArr.length == sArr2.length) {
            short[][] sArr3 = (short[][]) Array.newInstance(Short.TYPE, sArr.length, sArr2.length);
            for (int i = 0; i < sArr.length; i++) {
                for (int i2 = 0; i2 < sArr2.length; i2++) {
                    sArr3[i][i2] = GF2Field.multElem(sArr[i], sArr2[i2]);
                }
            }
            return sArr3;
        }
        throw new RuntimeException("Multiplication is not possible!");
    }

    public short[] multiplyMatrix(short[][] sArr, short[] sArr2) throws RuntimeException {
        if (sArr[0].length == sArr2.length) {
            short[] sArr3 = new short[sArr.length];
            for (int i = 0; i < sArr.length; i++) {
                for (int i2 = 0; i2 < sArr2.length; i2++) {
                    sArr3[i] = GF2Field.addElem(sArr3[i], GF2Field.multElem(sArr[i][i2], sArr2[i2]));
                }
            }
            return sArr3;
        }
        throw new RuntimeException("Multiplication is not possible!");
    }

    public short[][] multiplyMatrix(short[][] sArr, short[][] sArr2) throws RuntimeException {
        if (sArr[0].length == sArr2.length) {
            short[][] sArr3 = (short[][]) Array.newInstance(Short.TYPE, sArr.length, sArr2[0].length);
            for (int i = 0; i < sArr.length; i++) {
                for (int i2 = 0; i2 < sArr2.length; i2++) {
                    for (int i3 = 0; i3 < sArr2[0].length; i3++) {
                        short multElem = GF2Field.multElem(sArr[i][i2], sArr2[i2][i3]);
                        short[] sArr4 = sArr3[i];
                        sArr4[i3] = GF2Field.addElem(sArr4[i3], multElem);
                    }
                }
            }
            return sArr3;
        }
        throw new RuntimeException("Multiplication is not possible!");
    }

    public short multiplyMatrix_quad(short[][] sArr, short[] sArr2) throws RuntimeException {
        int length = sArr.length;
        short[] sArr3 = sArr[0];
        if (length == sArr3.length && sArr3.length == sArr2.length) {
            short[] sArr4 = new short[sArr.length];
            short s = 0;
            for (int i = 0; i < sArr.length; i++) {
                for (int i2 = 0; i2 < sArr2.length; i2++) {
                    sArr4[i] = GF2Field.addElem(sArr4[i], GF2Field.multElem(sArr[i][i2], sArr2[i2]));
                }
                s = GF2Field.addElem(s, GF2Field.multElem(sArr4[i], sArr2[i]));
            }
            return s;
        }
        throw new RuntimeException("Multiplication is not possible!");
    }

    public short[][][] obfuscate_l1_polys(short[][] sArr, short[][][] sArr2, short[][][] sArr3) {
        short[][] sArr4 = sArr2[0];
        int length = sArr4.length;
        short[][] sArr5 = sArr3[0];
        if (length == sArr5.length) {
            int length2 = sArr4[0].length;
            short[] sArr6 = sArr5[0];
            if (length2 == sArr6.length && sArr2.length == sArr[0].length && sArr3.length == sArr.length) {
                short[][][] sArr7 = (short[][][]) Array.newInstance(Short.TYPE, sArr3.length, sArr5.length, sArr6.length);
                for (int i = 0; i < sArr2[0].length; i++) {
                    for (int i2 = 0; i2 < sArr2[0][0].length; i2++) {
                        for (int i3 = 0; i3 < sArr.length; i3++) {
                            for (int i4 = 0; i4 < sArr[0].length; i4++) {
                                short multElem = GF2Field.multElem(sArr[i3][i4], sArr2[i4][i][i2]);
                                short[] sArr8 = sArr7[i3][i];
                                sArr8[i2] = GF2Field.addElem(sArr8[i2], multElem);
                            }
                            short[] sArr9 = sArr7[i3][i];
                            sArr9[i2] = GF2Field.addElem(sArr3[i3][i][i2], sArr9[i2]);
                        }
                    }
                }
                return sArr7;
            }
        }
        throw new RuntimeException("Multiplication not possible!");
    }

    public short[] solveEquation(short[][] sArr, short[] sArr2) {
        if (sArr.length != sArr2.length) {
            return null;
        }
        try {
            short[][] sArr3 = (short[][]) Array.newInstance(Short.TYPE, sArr.length, sArr.length + 1);
            short[] sArr4 = new short[sArr.length];
            for (int i = 0; i < sArr.length; i++) {
                System.arraycopy(sArr[i], 0, sArr3[i], 0, sArr[0].length);
                short[] sArr5 = sArr3[i];
                sArr5[sArr2.length] = GF2Field.addElem(sArr2[i], sArr5[sArr2.length]);
            }
            gaussElim(sArr3);
            for (int i2 = 0; i2 < sArr3.length; i2++) {
                sArr4[i2] = sArr3[i2][sArr2.length];
            }
            return sArr4;
        } catch (RuntimeException unused) {
            return null;
        }
    }

    public short[][] to_UT(short[][] sArr) {
        if (sArr.length == sArr[0].length) {
            short[][] sArr2 = (short[][]) Array.newInstance(Short.TYPE, sArr.length, sArr.length);
            int i = 0;
            while (i < sArr.length) {
                sArr2[i][i] = sArr[i][i];
                int i2 = i + 1;
                for (int i3 = i2; i3 < sArr[0].length; i3++) {
                    sArr2[i][i3] = GF2Field.addElem(sArr[i][i3], sArr[i3][i]);
                }
                i = i2;
            }
            return sArr2;
        }
        throw new RuntimeException("Computation to upper triangular matrix is not possible!");
    }

    public short[][] transpose(short[][] sArr) {
        short[][] sArr2 = (short[][]) Array.newInstance(Short.TYPE, sArr[0].length, sArr.length);
        for (int i = 0; i < sArr.length; i++) {
            for (int i2 = 0; i2 < sArr[0].length; i2++) {
                sArr2[i2][i] = sArr[i][i2];
            }
        }
        return sArr2;
    }
}