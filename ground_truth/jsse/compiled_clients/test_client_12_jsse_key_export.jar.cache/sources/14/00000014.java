package javassist;

import java.util.HashMap;
import javassist.bytecode.Descriptor;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/ClassMap.class */
public class ClassMap extends HashMap<String, String> {
    private static final long serialVersionUID = 1;
    private ClassMap parent;

    public ClassMap() {
        this.parent = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ClassMap(ClassMap map) {
        this.parent = map;
    }

    public void put(CtClass oldname, CtClass newname) {
        put(oldname.getName(), newname.getName());
    }

    @Override // java.util.HashMap, java.util.AbstractMap, java.util.Map
    public String put(String oldname, String newname) {
        if (oldname == newname) {
            return oldname;
        }
        String oldname2 = toJvmName(oldname);
        String s = get((Object) oldname2);
        if (s == null || !s.equals(oldname2)) {
            return (String) super.put((ClassMap) oldname2, toJvmName(newname));
        }
        return s;
    }

    public void putIfNone(String oldname, String newname) {
        if (oldname == newname) {
            return;
        }
        String oldname2 = toJvmName(oldname);
        String s = get((Object) oldname2);
        if (s == null) {
            super.put((ClassMap) oldname2, toJvmName(newname));
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final String put0(String oldname, String newname) {
        return (String) super.put((ClassMap) oldname, newname);
    }

    @Override // java.util.HashMap, java.util.AbstractMap, java.util.Map
    public String get(Object jvmClassName) {
        String found = (String) super.get(jvmClassName);
        if (found == null && this.parent != null) {
            return this.parent.get(jvmClassName);
        }
        return found;
    }

    public void fix(CtClass clazz) {
        fix(clazz.getName());
    }

    public void fix(String name) {
        String name2 = toJvmName(name);
        super.put((ClassMap) name2, name2);
    }

    public static String toJvmName(String classname) {
        return Descriptor.toJvmName(classname);
    }

    public static String toJavaName(String classname) {
        return Descriptor.toJavaName(classname);
    }
}