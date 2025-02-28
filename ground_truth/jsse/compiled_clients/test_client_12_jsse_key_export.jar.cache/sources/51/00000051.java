package javassist.bytecode;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javassist.bytecode.annotation.Annotation;
import javassist.bytecode.annotation.AnnotationMemberValue;
import javassist.bytecode.annotation.AnnotationsWriter;
import javassist.bytecode.annotation.ArrayMemberValue;
import javassist.bytecode.annotation.BooleanMemberValue;
import javassist.bytecode.annotation.ByteMemberValue;
import javassist.bytecode.annotation.CharMemberValue;
import javassist.bytecode.annotation.ClassMemberValue;
import javassist.bytecode.annotation.DoubleMemberValue;
import javassist.bytecode.annotation.EnumMemberValue;
import javassist.bytecode.annotation.FloatMemberValue;
import javassist.bytecode.annotation.IntegerMemberValue;
import javassist.bytecode.annotation.LongMemberValue;
import javassist.bytecode.annotation.MemberValue;
import javassist.bytecode.annotation.ShortMemberValue;
import javassist.bytecode.annotation.StringMemberValue;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/AnnotationsAttribute.class */
public class AnnotationsAttribute extends AttributeInfo {
    public static final String visibleTag = "RuntimeVisibleAnnotations";
    public static final String invisibleTag = "RuntimeInvisibleAnnotations";

    public AnnotationsAttribute(ConstPool cp, String attrname, byte[] info) {
        super(cp, attrname, info);
    }

    public AnnotationsAttribute(ConstPool cp, String attrname) {
        this(cp, attrname, new byte[]{0, 0});
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public AnnotationsAttribute(ConstPool cp, int n, DataInputStream in) throws IOException {
        super(cp, n, in);
    }

    public int numAnnotations() {
        return ByteArray.readU16bit(this.info, 0);
    }

    @Override // javassist.bytecode.AttributeInfo
    public AttributeInfo copy(ConstPool newCp, Map<String, String> classnames) {
        Copier copier = new Copier(this.info, this.constPool, newCp, classnames);
        try {
            copier.annotationArray();
            return new AnnotationsAttribute(newCp, getName(), copier.close());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Annotation getAnnotation(String type) {
        Annotation[] annotations = getAnnotations();
        for (int i = 0; i < annotations.length; i++) {
            if (annotations[i].getTypeName().equals(type)) {
                return annotations[i];
            }
        }
        return null;
    }

    public void addAnnotation(Annotation annotation) {
        String type = annotation.getTypeName();
        Annotation[] annotations = getAnnotations();
        for (int i = 0; i < annotations.length; i++) {
            if (annotations[i].getTypeName().equals(type)) {
                annotations[i] = annotation;
                setAnnotations(annotations);
                return;
            }
        }
        Annotation[] newlist = new Annotation[annotations.length + 1];
        System.arraycopy(annotations, 0, newlist, 0, annotations.length);
        newlist[annotations.length] = annotation;
        setAnnotations(newlist);
    }

    public boolean removeAnnotation(String type) {
        Annotation[] annotations = getAnnotations();
        for (int i = 0; i < annotations.length; i++) {
            if (annotations[i].getTypeName().equals(type)) {
                Annotation[] newlist = new Annotation[annotations.length - 1];
                System.arraycopy(annotations, 0, newlist, 0, i);
                if (i < annotations.length - 1) {
                    System.arraycopy(annotations, i + 1, newlist, i, (annotations.length - i) - 1);
                }
                setAnnotations(newlist);
                return true;
            }
        }
        return false;
    }

    public Annotation[] getAnnotations() {
        try {
            return new Parser(this.info, this.constPool).parseAnnotations();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void setAnnotations(Annotation[] annotations) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        AnnotationsWriter writer = new AnnotationsWriter(output, this.constPool);
        try {
            int n = annotations.length;
            writer.numAnnotations(n);
            for (Annotation annotation : annotations) {
                annotation.write(writer);
            }
            writer.close();
            set(output.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void setAnnotation(Annotation annotation) {
        setAnnotations(new Annotation[]{annotation});
    }

    @Override // javassist.bytecode.AttributeInfo
    void renameClass(String oldname, String newname) {
        Map<String, String> map = new HashMap<>();
        map.put(oldname, newname);
        renameClass(map);
    }

    @Override // javassist.bytecode.AttributeInfo
    void renameClass(Map<String, String> classnames) {
        Renamer renamer = new Renamer(this.info, getConstPool(), classnames);
        try {
            renamer.annotationArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override // javassist.bytecode.AttributeInfo
    void getRefClasses(Map<String, String> classnames) {
        renameClass(classnames);
    }

    public String toString() {
        Annotation[] a = getAnnotations();
        StringBuilder sbuf = new StringBuilder();
        int i = 0;
        while (i < a.length) {
            int i2 = i;
            i++;
            sbuf.append(a[i2].toString());
            if (i != a.length) {
                sbuf.append(", ");
            }
        }
        return sbuf.toString();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/AnnotationsAttribute$Walker.class */
    public static class Walker {
        byte[] info;

        /* JADX INFO: Access modifiers changed from: package-private */
        public Walker(byte[] attrInfo) {
            this.info = attrInfo;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public final void parameters() throws Exception {
            int numParam = this.info[0] & 255;
            parameters(numParam, 1);
        }

        void parameters(int numParam, int pos) throws Exception {
            for (int i = 0; i < numParam; i++) {
                pos = annotationArray(pos);
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public final void annotationArray() throws Exception {
            annotationArray(0);
        }

        final int annotationArray(int pos) throws Exception {
            int num = ByteArray.readU16bit(this.info, pos);
            return annotationArray(pos + 2, num);
        }

        int annotationArray(int pos, int num) throws Exception {
            for (int i = 0; i < num; i++) {
                pos = annotation(pos);
            }
            return pos;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public final int annotation(int pos) throws Exception {
            int type = ByteArray.readU16bit(this.info, pos);
            int numPairs = ByteArray.readU16bit(this.info, pos + 2);
            return annotation(pos + 4, type, numPairs);
        }

        int annotation(int pos, int type, int numPairs) throws Exception {
            for (int j = 0; j < numPairs; j++) {
                pos = memberValuePair(pos);
            }
            return pos;
        }

        final int memberValuePair(int pos) throws Exception {
            int nameIndex = ByteArray.readU16bit(this.info, pos);
            return memberValuePair(pos + 2, nameIndex);
        }

        int memberValuePair(int pos, int nameIndex) throws Exception {
            return memberValue(pos);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public final int memberValue(int pos) throws Exception {
            int tag = this.info[pos] & 255;
            if (tag == 101) {
                int typeNameIndex = ByteArray.readU16bit(this.info, pos + 1);
                int constNameIndex = ByteArray.readU16bit(this.info, pos + 3);
                enumMemberValue(pos, typeNameIndex, constNameIndex);
                return pos + 5;
            } else if (tag == 99) {
                int index = ByteArray.readU16bit(this.info, pos + 1);
                classMemberValue(pos, index);
                return pos + 3;
            } else if (tag == 64) {
                return annotationMemberValue(pos + 1);
            } else {
                if (tag == 91) {
                    int num = ByteArray.readU16bit(this.info, pos + 1);
                    return arrayMemberValue(pos + 3, num);
                }
                int index2 = ByteArray.readU16bit(this.info, pos + 1);
                constValueMember(tag, index2);
                return pos + 3;
            }
        }

        void constValueMember(int tag, int index) throws Exception {
        }

        void enumMemberValue(int pos, int typeNameIndex, int constNameIndex) throws Exception {
        }

        void classMemberValue(int pos, int index) throws Exception {
        }

        int annotationMemberValue(int pos) throws Exception {
            return annotation(pos);
        }

        int arrayMemberValue(int pos, int num) throws Exception {
            for (int i = 0; i < num; i++) {
                pos = memberValue(pos);
            }
            return pos;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/AnnotationsAttribute$Renamer.class */
    public static class Renamer extends Walker {
        ConstPool cpool;
        Map<String, String> classnames;

        /* JADX INFO: Access modifiers changed from: package-private */
        public Renamer(byte[] info, ConstPool cp, Map<String, String> map) {
            super(info);
            this.cpool = cp;
            this.classnames = map;
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        int annotation(int pos, int type, int numPairs) throws Exception {
            renameType(pos - 4, type);
            return super.annotation(pos, type, numPairs);
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        void enumMemberValue(int pos, int typeNameIndex, int constNameIndex) throws Exception {
            renameType(pos + 1, typeNameIndex);
            super.enumMemberValue(pos, typeNameIndex, constNameIndex);
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        void classMemberValue(int pos, int index) throws Exception {
            renameType(pos + 1, index);
            super.classMemberValue(pos, index);
        }

        private void renameType(int pos, int index) {
            String name = this.cpool.getUtf8Info(index);
            String newName = Descriptor.rename(name, this.classnames);
            if (!name.equals(newName)) {
                int index2 = this.cpool.addUtf8Info(newName);
                ByteArray.write16bit(index2, this.info, pos);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/AnnotationsAttribute$Copier.class */
    static class Copier extends Walker {
        ByteArrayOutputStream output;
        AnnotationsWriter writer;
        ConstPool srcPool;
        ConstPool destPool;
        Map<String, String> classnames;

        /* JADX INFO: Access modifiers changed from: package-private */
        public Copier(byte[] info, ConstPool src, ConstPool dest, Map<String, String> map) {
            this(info, src, dest, map, true);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public Copier(byte[] info, ConstPool src, ConstPool dest, Map<String, String> map, boolean makeWriter) {
            super(info);
            this.output = new ByteArrayOutputStream();
            if (makeWriter) {
                this.writer = new AnnotationsWriter(this.output, dest);
            }
            this.srcPool = src;
            this.destPool = dest;
            this.classnames = map;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public byte[] close() throws IOException {
            this.writer.close();
            return this.output.toByteArray();
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        void parameters(int numParam, int pos) throws Exception {
            this.writer.numParameters(numParam);
            super.parameters(numParam, pos);
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        int annotationArray(int pos, int num) throws Exception {
            this.writer.numAnnotations(num);
            return super.annotationArray(pos, num);
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        int annotation(int pos, int type, int numPairs) throws Exception {
            this.writer.annotation(copyType(type), numPairs);
            return super.annotation(pos, type, numPairs);
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        int memberValuePair(int pos, int nameIndex) throws Exception {
            this.writer.memberValuePair(copy(nameIndex));
            return super.memberValuePair(pos, nameIndex);
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        void constValueMember(int tag, int index) throws Exception {
            this.writer.constValueIndex(tag, copy(index));
            super.constValueMember(tag, index);
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        void enumMemberValue(int pos, int typeNameIndex, int constNameIndex) throws Exception {
            this.writer.enumConstValue(copyType(typeNameIndex), copy(constNameIndex));
            super.enumMemberValue(pos, typeNameIndex, constNameIndex);
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        void classMemberValue(int pos, int index) throws Exception {
            this.writer.classInfoIndex(copyType(index));
            super.classMemberValue(pos, index);
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        int annotationMemberValue(int pos) throws Exception {
            this.writer.annotationValue();
            return super.annotationMemberValue(pos);
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        int arrayMemberValue(int pos, int num) throws Exception {
            this.writer.arrayValue(num);
            return super.arrayMemberValue(pos, num);
        }

        int copy(int srcIndex) {
            return this.srcPool.copy(srcIndex, this.destPool, this.classnames);
        }

        int copyType(int srcIndex) {
            String name = this.srcPool.getUtf8Info(srcIndex);
            String newName = Descriptor.rename(name, this.classnames);
            return this.destPool.addUtf8Info(newName);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/AnnotationsAttribute$Parser.class */
    public static class Parser extends Walker {
        ConstPool pool;
        Annotation[][] allParams;
        Annotation[] allAnno;
        Annotation currentAnno;
        MemberValue currentMember;

        /* JADX INFO: Access modifiers changed from: package-private */
        public Parser(byte[] info, ConstPool cp) {
            super(info);
            this.pool = cp;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public Annotation[][] parseParameters() throws Exception {
            parameters();
            return this.allParams;
        }

        Annotation[] parseAnnotations() throws Exception {
            annotationArray();
            return this.allAnno;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public MemberValue parseMemberValue() throws Exception {
            memberValue(0);
            return this.currentMember;
        }

        /* JADX WARN: Type inference failed for: r0v1, types: [javassist.bytecode.annotation.Annotation[], javassist.bytecode.annotation.Annotation[][]] */
        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        void parameters(int numParam, int pos) throws Exception {
            ?? r0 = new Annotation[numParam];
            for (int i = 0; i < numParam; i++) {
                pos = annotationArray(pos);
                r0[i] = this.allAnno;
            }
            this.allParams = r0;
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        int annotationArray(int pos, int num) throws Exception {
            Annotation[] array = new Annotation[num];
            for (int i = 0; i < num; i++) {
                pos = annotation(pos);
                array[i] = this.currentAnno;
            }
            this.allAnno = array;
            return pos;
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        int annotation(int pos, int type, int numPairs) throws Exception {
            this.currentAnno = new Annotation(type, this.pool);
            return super.annotation(pos, type, numPairs);
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        int memberValuePair(int pos, int nameIndex) throws Exception {
            int pos2 = super.memberValuePair(pos, nameIndex);
            this.currentAnno.addMemberValue(nameIndex, this.currentMember);
            return pos2;
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        void constValueMember(int tag, int index) throws Exception {
            MemberValue m;
            ConstPool cp = this.pool;
            switch (tag) {
                case 66:
                    m = new ByteMemberValue(index, cp);
                    break;
                case 67:
                    m = new CharMemberValue(index, cp);
                    break;
                case 68:
                    m = new DoubleMemberValue(index, cp);
                    break;
                case 70:
                    m = new FloatMemberValue(index, cp);
                    break;
                case 73:
                    m = new IntegerMemberValue(index, cp);
                    break;
                case Opcode.DSTORE_3 /* 74 */:
                    m = new LongMemberValue(index, cp);
                    break;
                case Opcode.AASTORE /* 83 */:
                    m = new ShortMemberValue(index, cp);
                    break;
                case 90:
                    m = new BooleanMemberValue(index, cp);
                    break;
                case Opcode.DREM /* 115 */:
                    m = new StringMemberValue(index, cp);
                    break;
                default:
                    throw new RuntimeException("unknown tag:" + tag);
            }
            this.currentMember = m;
            super.constValueMember(tag, index);
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        void enumMemberValue(int pos, int typeNameIndex, int constNameIndex) throws Exception {
            this.currentMember = new EnumMemberValue(typeNameIndex, constNameIndex, this.pool);
            super.enumMemberValue(pos, typeNameIndex, constNameIndex);
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        void classMemberValue(int pos, int index) throws Exception {
            this.currentMember = new ClassMemberValue(index, this.pool);
            super.classMemberValue(pos, index);
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        int annotationMemberValue(int pos) throws Exception {
            Annotation anno = this.currentAnno;
            int pos2 = super.annotationMemberValue(pos);
            this.currentMember = new AnnotationMemberValue(this.currentAnno, this.pool);
            this.currentAnno = anno;
            return pos2;
        }

        @Override // javassist.bytecode.AnnotationsAttribute.Walker
        int arrayMemberValue(int pos, int num) throws Exception {
            ArrayMemberValue amv = new ArrayMemberValue(this.pool);
            MemberValue[] elements = new MemberValue[num];
            for (int i = 0; i < num; i++) {
                pos = memberValue(pos);
                elements[i] = this.currentMember;
            }
            amv.setValue(elements);
            this.currentMember = amv;
            return pos;
        }
    }
}