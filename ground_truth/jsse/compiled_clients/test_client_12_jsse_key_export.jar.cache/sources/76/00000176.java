package javassist.tools.reflect;

import java.io.PrintStream;
import javassist.ClassPool;
import javassist.CtClass;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/tools/reflect/Compiler.class */
public class Compiler {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            help(System.err);
            return;
        }
        CompiledClass[] entries = new CompiledClass[args.length];
        int n = parse(args, entries);
        if (n < 1) {
            System.err.println("bad parameter.");
        } else {
            processClasses(entries, n);
        }
    }

    private static void processClasses(CompiledClass[] entries, int n) throws Exception {
        String metaobj;
        String classobj;
        Reflection implementor = new Reflection();
        ClassPool pool = ClassPool.getDefault();
        implementor.start(pool);
        for (int i = 0; i < n; i++) {
            CtClass c = pool.get(entries[i].classname);
            if (entries[i].metaobject != null || entries[i].classobject != null) {
                if (entries[i].metaobject == null) {
                    metaobj = "javassist.tools.reflect.Metaobject";
                } else {
                    metaobj = entries[i].metaobject;
                }
                if (entries[i].classobject == null) {
                    classobj = "javassist.tools.reflect.ClassMetaobject";
                } else {
                    classobj = entries[i].classobject;
                }
                if (!implementor.makeReflective(c, pool.get(metaobj), pool.get(classobj))) {
                    System.err.println("Warning: " + c.getName() + " is reflective.  It was not changed.");
                }
                System.err.println(c.getName() + ": " + metaobj + ", " + classobj);
            } else {
                System.err.println(c.getName() + ": not reflective");
            }
        }
        for (int i2 = 0; i2 < n; i2++) {
            implementor.onLoad(pool, entries[i2].classname);
            pool.get(entries[i2].classname).writeFile();
        }
    }

    private static int parse(String[] args, CompiledClass[] result) {
        int n = -1;
        int i = 0;
        while (i < args.length) {
            String a = args[i];
            if (a.equals("-m")) {
                if (n < 0 || i + 1 > args.length) {
                    return -1;
                }
                i++;
                result[n].metaobject = args[i];
            } else if (a.equals("-c")) {
                if (n < 0 || i + 1 > args.length) {
                    return -1;
                }
                i++;
                result[n].classobject = args[i];
            } else if (a.charAt(0) == '-') {
                return -1;
            } else {
                CompiledClass cc = new CompiledClass();
                cc.classname = a;
                cc.metaobject = null;
                cc.classobject = null;
                n++;
                result[n] = cc;
            }
            i++;
        }
        return n + 1;
    }

    private static void help(PrintStream out) {
        out.println("Usage: java javassist.tools.reflect.Compiler");
        out.println("            (<class> [-m <metaobject>] [-c <class metaobject>])+");
    }
}