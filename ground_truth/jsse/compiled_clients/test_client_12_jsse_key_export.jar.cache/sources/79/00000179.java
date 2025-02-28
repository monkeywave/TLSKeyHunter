package javassist.tools.reflect;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/tools/reflect/Metaobject.class */
public class Metaobject implements Serializable {
    private static final long serialVersionUID = 1;
    protected ClassMetaobject classmetaobject;
    protected Metalevel baseobject;
    protected Method[] methods;

    public Metaobject(Object self, Object[] args) {
        this.baseobject = (Metalevel) self;
        this.classmetaobject = this.baseobject._getClass();
        this.methods = this.classmetaobject.getReflectiveMethods();
    }

    protected Metaobject() {
        this.baseobject = null;
        this.classmetaobject = null;
        this.methods = null;
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeObject(this.baseobject);
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        this.baseobject = (Metalevel) in.readObject();
        this.classmetaobject = this.baseobject._getClass();
        this.methods = this.classmetaobject.getReflectiveMethods();
    }

    public final ClassMetaobject getClassMetaobject() {
        return this.classmetaobject;
    }

    public final Object getObject() {
        return this.baseobject;
    }

    public final void setObject(Object self) {
        this.baseobject = (Metalevel) self;
        this.classmetaobject = this.baseobject._getClass();
        this.methods = this.classmetaobject.getReflectiveMethods();
        this.baseobject._setMetaobject(this);
    }

    public final String getMethodName(int identifier) {
        char c;
        String mname = this.methods[identifier].getName();
        int j = 3;
        do {
            int i = j;
            j++;
            c = mname.charAt(i);
            if (c < '0') {
                break;
            }
        } while ('9' >= c);
        return mname.substring(j);
    }

    public final Class<?>[] getParameterTypes(int identifier) {
        return this.methods[identifier].getParameterTypes();
    }

    public final Class<?> getReturnType(int identifier) {
        return this.methods[identifier].getReturnType();
    }

    public Object trapFieldRead(String name) {
        Class<?> jc = getClassMetaobject().getJavaClass();
        try {
            return jc.getField(name).get(getObject());
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e.toString());
        } catch (NoSuchFieldException e2) {
            throw new RuntimeException(e2.toString());
        }
    }

    public void trapFieldWrite(String name, Object value) {
        Class<?> jc = getClassMetaobject().getJavaClass();
        try {
            jc.getField(name).set(getObject(), value);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e.toString());
        } catch (NoSuchFieldException e2) {
            throw new RuntimeException(e2.toString());
        }
    }

    public Object trapMethodcall(int identifier, Object[] args) throws Throwable {
        try {
            return this.methods[identifier].invoke(getObject(), args);
        } catch (IllegalAccessException e) {
            throw new CannotInvokeException(e);
        } catch (InvocationTargetException e2) {
            throw e2.getTargetException();
        }
    }
}