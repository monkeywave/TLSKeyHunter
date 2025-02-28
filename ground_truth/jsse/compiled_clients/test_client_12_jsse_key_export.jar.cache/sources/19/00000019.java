package javassist;

import javassist.bytecode.BadBytecode;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ConstPool;
import javassist.bytecode.MethodInfo;
import javassist.convert.TransformAccessArrayField;
import javassist.convert.TransformAfter;
import javassist.convert.TransformBefore;
import javassist.convert.TransformCall;
import javassist.convert.TransformCallToStatic;
import javassist.convert.TransformFieldAccess;
import javassist.convert.TransformNew;
import javassist.convert.TransformNewClass;
import javassist.convert.TransformReadField;
import javassist.convert.TransformWriteField;
import javassist.convert.Transformer;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/CodeConverter.class */
public class CodeConverter {
    protected Transformer transformers = null;

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/CodeConverter$ArrayAccessReplacementMethodNames.class */
    public interface ArrayAccessReplacementMethodNames {
        String byteOrBooleanRead();

        String byteOrBooleanWrite();

        String charRead();

        String charWrite();

        String doubleRead();

        String doubleWrite();

        String floatRead();

        String floatWrite();

        String intRead();

        String intWrite();

        String longRead();

        String longWrite();

        String objectRead();

        String objectWrite();

        String shortRead();

        String shortWrite();
    }

    public void replaceNew(CtClass newClass, CtClass calledClass, String calledMethod) {
        this.transformers = new TransformNew(this.transformers, newClass.getName(), calledClass.getName(), calledMethod);
    }

    public void replaceNew(CtClass oldClass, CtClass newClass) {
        this.transformers = new TransformNewClass(this.transformers, oldClass.getName(), newClass.getName());
    }

    public void redirectFieldAccess(CtField field, CtClass newClass, String newFieldname) {
        this.transformers = new TransformFieldAccess(this.transformers, field, newClass.getName(), newFieldname);
    }

    public void replaceFieldRead(CtField field, CtClass calledClass, String calledMethod) {
        this.transformers = new TransformReadField(this.transformers, field, calledClass.getName(), calledMethod);
    }

    public void replaceFieldWrite(CtField field, CtClass calledClass, String calledMethod) {
        this.transformers = new TransformWriteField(this.transformers, field, calledClass.getName(), calledMethod);
    }

    public void replaceArrayAccess(CtClass calledClass, ArrayAccessReplacementMethodNames names) throws NotFoundException {
        this.transformers = new TransformAccessArrayField(this.transformers, calledClass.getName(), names);
    }

    public void redirectMethodCall(CtMethod origMethod, CtMethod substMethod) throws CannotCompileException {
        String d1 = origMethod.getMethodInfo2().getDescriptor();
        String d2 = substMethod.getMethodInfo2().getDescriptor();
        if (!d1.equals(d2)) {
            throw new CannotCompileException("signature mismatch: " + substMethod.getLongName());
        }
        int mod1 = origMethod.getModifiers();
        int mod2 = substMethod.getModifiers();
        if (Modifier.isStatic(mod1) != Modifier.isStatic(mod2) || ((Modifier.isPrivate(mod1) && !Modifier.isPrivate(mod2)) || origMethod.getDeclaringClass().isInterface() != substMethod.getDeclaringClass().isInterface())) {
            throw new CannotCompileException("invoke-type mismatch " + substMethod.getLongName());
        }
        this.transformers = new TransformCall(this.transformers, origMethod, substMethod);
    }

    public void redirectMethodCall(String oldMethodName, CtMethod newMethod) throws CannotCompileException {
        this.transformers = new TransformCall(this.transformers, oldMethodName, newMethod);
    }

    public void redirectMethodCallToStatic(CtMethod origMethod, CtMethod staticMethod) {
        this.transformers = new TransformCallToStatic(this.transformers, origMethod, staticMethod);
    }

    public void insertBeforeMethod(CtMethod origMethod, CtMethod beforeMethod) throws CannotCompileException {
        try {
            this.transformers = new TransformBefore(this.transformers, origMethod, beforeMethod);
        } catch (NotFoundException e) {
            throw new CannotCompileException(e);
        }
    }

    public void insertAfterMethod(CtMethod origMethod, CtMethod afterMethod) throws CannotCompileException {
        try {
            this.transformers = new TransformAfter(this.transformers, origMethod, afterMethod);
        } catch (NotFoundException e) {
            throw new CannotCompileException(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void doit(CtClass clazz, MethodInfo minfo, ConstPool cp) throws CannotCompileException {
        CodeAttribute codeAttr = minfo.getCodeAttribute();
        if (codeAttr == null || this.transformers == null) {
            return;
        }
        Transformer transformer = this.transformers;
        while (true) {
            Transformer t = transformer;
            if (t == null) {
                break;
            }
            t.initialize(cp, clazz, minfo);
            transformer = t.getNext();
        }
        CodeIterator iterator = codeAttr.iterator();
        while (iterator.hasNext()) {
            try {
                int pos = iterator.next();
                for (Transformer t2 = this.transformers; t2 != null; t2 = t2.getNext()) {
                    pos = t2.transform(clazz, pos, iterator, cp);
                }
            } catch (BadBytecode e) {
                throw new CannotCompileException(e);
            }
        }
        int locals = 0;
        int stack = 0;
        Transformer transformer2 = this.transformers;
        while (true) {
            Transformer t3 = transformer2;
            if (t3 == null) {
                break;
            }
            int s = t3.extraLocals();
            if (s > locals) {
                locals = s;
            }
            int s2 = t3.extraStack();
            if (s2 > stack) {
                stack = s2;
            }
            transformer2 = t3.getNext();
        }
        Transformer transformer3 = this.transformers;
        while (true) {
            Transformer t4 = transformer3;
            if (t4 == null) {
                break;
            }
            t4.clean();
            transformer3 = t4.getNext();
        }
        if (locals > 0) {
            codeAttr.setMaxLocals(codeAttr.getMaxLocals() + locals);
        }
        if (stack > 0) {
            codeAttr.setMaxStack(codeAttr.getMaxStack() + stack);
        }
        try {
            minfo.rebuildStackMapIf6(clazz.getClassPool(), clazz.getClassFile2());
        } catch (BadBytecode b) {
            throw new CannotCompileException(b.getMessage(), b);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/CodeConverter$DefaultArrayAccessReplacementMethodNames.class */
    public static class DefaultArrayAccessReplacementMethodNames implements ArrayAccessReplacementMethodNames {
        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String byteOrBooleanRead() {
            return "arrayReadByteOrBoolean";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String byteOrBooleanWrite() {
            return "arrayWriteByteOrBoolean";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String charRead() {
            return "arrayReadChar";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String charWrite() {
            return "arrayWriteChar";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String doubleRead() {
            return "arrayReadDouble";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String doubleWrite() {
            return "arrayWriteDouble";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String floatRead() {
            return "arrayReadFloat";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String floatWrite() {
            return "arrayWriteFloat";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String intRead() {
            return "arrayReadInt";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String intWrite() {
            return "arrayWriteInt";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String longRead() {
            return "arrayReadLong";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String longWrite() {
            return "arrayWriteLong";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String objectRead() {
            return "arrayReadObject";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String objectWrite() {
            return "arrayWriteObject";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String shortRead() {
            return "arrayReadShort";
        }

        @Override // javassist.CodeConverter.ArrayAccessReplacementMethodNames
        public String shortWrite() {
            return "arrayWriteShort";
        }
    }
}