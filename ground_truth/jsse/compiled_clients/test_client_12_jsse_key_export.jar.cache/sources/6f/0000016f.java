package javassist.tools;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import javassist.bytecode.ClassFile;
import javassist.bytecode.ClassFilePrinter;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/tools/Dump.class */
public class Dump {
    private Dump() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: java Dump <class file name>");
            return;
        }
        DataInputStream in = new DataInputStream(new FileInputStream(args[0]));
        ClassFile w = new ClassFile(in);
        PrintWriter out = new PrintWriter((OutputStream) System.out, true);
        out.println("*** constant pool ***");
        w.getConstPool().print(out);
        out.println();
        out.println("*** members ***");
        ClassFilePrinter.print(w, out);
    }
}