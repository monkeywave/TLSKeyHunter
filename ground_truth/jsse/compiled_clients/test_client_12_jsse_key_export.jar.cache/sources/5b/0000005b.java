package javassist.bytecode;

import java.io.IOException;
import java.io.OutputStream;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/ByteStream.class */
final class ByteStream extends OutputStream {
    private byte[] buf;
    private int count;

    public ByteStream() {
        this(32);
    }

    public ByteStream(int size) {
        this.buf = new byte[size];
        this.count = 0;
    }

    public int getPos() {
        return this.count;
    }

    public int size() {
        return this.count;
    }

    public void writeBlank(int len) {
        enlarge(len);
        this.count += len;
    }

    @Override // java.io.OutputStream
    public void write(byte[] data) {
        write(data, 0, data.length);
    }

    @Override // java.io.OutputStream
    public void write(byte[] data, int off, int len) {
        enlarge(len);
        System.arraycopy(data, off, this.buf, this.count, len);
        this.count += len;
    }

    @Override // java.io.OutputStream
    public void write(int b) {
        enlarge(1);
        int oldCount = this.count;
        this.buf[oldCount] = (byte) b;
        this.count = oldCount + 1;
    }

    public void writeShort(int s) {
        enlarge(2);
        int oldCount = this.count;
        this.buf[oldCount] = (byte) (s >>> 8);
        this.buf[oldCount + 1] = (byte) s;
        this.count = oldCount + 2;
    }

    public void writeInt(int i) {
        enlarge(4);
        int oldCount = this.count;
        this.buf[oldCount] = (byte) (i >>> 24);
        this.buf[oldCount + 1] = (byte) (i >>> 16);
        this.buf[oldCount + 2] = (byte) (i >>> 8);
        this.buf[oldCount + 3] = (byte) i;
        this.count = oldCount + 4;
    }

    public void writeLong(long i) {
        enlarge(8);
        int oldCount = this.count;
        this.buf[oldCount] = (byte) (i >>> 56);
        this.buf[oldCount + 1] = (byte) (i >>> 48);
        this.buf[oldCount + 2] = (byte) (i >>> 40);
        this.buf[oldCount + 3] = (byte) (i >>> 32);
        this.buf[oldCount + 4] = (byte) (i >>> 24);
        this.buf[oldCount + 5] = (byte) (i >>> 16);
        this.buf[oldCount + 6] = (byte) (i >>> 8);
        this.buf[oldCount + 7] = (byte) i;
        this.count = oldCount + 8;
    }

    public void writeFloat(float v) {
        writeInt(Float.floatToIntBits(v));
    }

    public void writeDouble(double v) {
        writeLong(Double.doubleToLongBits(v));
    }

    public void writeUTF(String s) {
        int sLen = s.length();
        int pos = this.count;
        enlarge(sLen + 2);
        byte[] buffer = this.buf;
        int pos2 = pos + 1;
        buffer[pos] = (byte) (sLen >>> 8);
        int pos3 = pos2 + 1;
        buffer[pos2] = (byte) sLen;
        for (int i = 0; i < sLen; i++) {
            char c = s.charAt(i);
            if (1 <= c && c <= 127) {
                int i2 = pos3;
                pos3++;
                buffer[i2] = (byte) c;
            } else {
                writeUTF2(s, sLen, i);
                return;
            }
        }
        this.count = pos3;
    }

    private void writeUTF2(String s, int sLen, int offset) {
        int size = sLen;
        for (int i = offset; i < sLen; i++) {
            int c = s.charAt(i);
            if (c > 2047) {
                size += 2;
            } else if (c == 0 || c > 127) {
                size++;
            }
        }
        if (size > 65535) {
            throw new RuntimeException("encoded string too long: " + sLen + size + " bytes");
        }
        enlarge(size + 2);
        int pos = this.count;
        byte[] buffer = this.buf;
        buffer[pos] = (byte) (size >>> 8);
        buffer[pos + 1] = (byte) size;
        int pos2 = pos + 2 + offset;
        for (int j = offset; j < sLen; j++) {
            int c2 = s.charAt(j);
            if (1 <= c2 && c2 <= 127) {
                int i2 = pos2;
                pos2++;
                buffer[i2] = (byte) c2;
            } else if (c2 > 2047) {
                buffer[pos2] = (byte) (224 | ((c2 >> 12) & 15));
                buffer[pos2 + 1] = (byte) (128 | ((c2 >> 6) & 63));
                buffer[pos2 + 2] = (byte) (128 | (c2 & 63));
                pos2 += 3;
            } else {
                buffer[pos2] = (byte) (192 | ((c2 >> 6) & 31));
                buffer[pos2 + 1] = (byte) (128 | (c2 & 63));
                pos2 += 2;
            }
        }
        this.count = pos2;
    }

    public void write(int pos, int value) {
        this.buf[pos] = (byte) value;
    }

    public void writeShort(int pos, int value) {
        this.buf[pos] = (byte) (value >>> 8);
        this.buf[pos + 1] = (byte) value;
    }

    public void writeInt(int pos, int value) {
        this.buf[pos] = (byte) (value >>> 24);
        this.buf[pos + 1] = (byte) (value >>> 16);
        this.buf[pos + 2] = (byte) (value >>> 8);
        this.buf[pos + 3] = (byte) value;
    }

    public byte[] toByteArray() {
        byte[] buf2 = new byte[this.count];
        System.arraycopy(this.buf, 0, buf2, 0, this.count);
        return buf2;
    }

    public void writeTo(OutputStream out) throws IOException {
        out.write(this.buf, 0, this.count);
    }

    public void enlarge(int delta) {
        int newCount = this.count + delta;
        if (newCount > this.buf.length) {
            int newLen = this.buf.length << 1;
            byte[] newBuf = new byte[newLen > newCount ? newLen : newCount];
            System.arraycopy(this.buf, 0, newBuf, 0, this.count);
            this.buf = newBuf;
        }
    }
}