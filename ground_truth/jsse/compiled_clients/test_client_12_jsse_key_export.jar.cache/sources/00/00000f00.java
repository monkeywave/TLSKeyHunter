package org.bouncycastle.util.p012io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javassist.bytecode.AccessFlag;

/* renamed from: org.bouncycastle.util.io.Streams */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/io/Streams.class */
public final class Streams {
    private static int BUFFER_SIZE = AccessFlag.SYNTHETIC;

    public static void drain(InputStream inputStream) throws IOException {
        byte[] bArr = new byte[BUFFER_SIZE];
        do {
        } while (inputStream.read(bArr, 0, bArr.length) >= 0);
    }

    public static byte[] readAll(InputStream inputStream) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        pipeAll(inputStream, byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    public static byte[] readAllLimited(InputStream inputStream, int i) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        pipeAllLimited(inputStream, i, byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    public static int readFully(InputStream inputStream, byte[] bArr) throws IOException {
        return readFully(inputStream, bArr, 0, bArr.length);
    }

    public static int readFully(InputStream inputStream, byte[] bArr, int i, int i2) throws IOException {
        int i3;
        int read;
        int i4 = 0;
        while (true) {
            i3 = i4;
            if (i3 >= i2 || (read = inputStream.read(bArr, i + i3, i2 - i3)) < 0) {
                break;
            }
            i4 = i3 + read;
        }
        return i3;
    }

    public static void pipeAll(InputStream inputStream, OutputStream outputStream) throws IOException {
        pipeAll(inputStream, outputStream, BUFFER_SIZE);
    }

    public static void pipeAll(InputStream inputStream, OutputStream outputStream, int i) throws IOException {
        byte[] bArr = new byte[i];
        while (true) {
            int read = inputStream.read(bArr, 0, bArr.length);
            if (read < 0) {
                return;
            }
            outputStream.write(bArr, 0, read);
        }
    }

    public static long pipeAllLimited(InputStream inputStream, long j, OutputStream outputStream) throws IOException {
        long j2 = 0;
        byte[] bArr = new byte[BUFFER_SIZE];
        while (true) {
            int read = inputStream.read(bArr, 0, bArr.length);
            if (read < 0) {
                return j2;
            }
            if (j - j2 < read) {
                throw new StreamOverflowException("Data Overflow");
            }
            j2 += read;
            outputStream.write(bArr, 0, read);
        }
    }

    public static void writeBufTo(ByteArrayOutputStream byteArrayOutputStream, OutputStream outputStream) throws IOException {
        byteArrayOutputStream.writeTo(outputStream);
    }
}