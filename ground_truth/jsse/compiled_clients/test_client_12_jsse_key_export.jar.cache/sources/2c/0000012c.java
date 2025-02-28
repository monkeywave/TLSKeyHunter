package javassist.compiler.ast;

import javassist.compiler.CompileError;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/ast/ASTList.class */
public class ASTList extends ASTree {
    private static final long serialVersionUID = 1;
    private ASTree left;
    private ASTList right;

    public ASTList(ASTree _head, ASTList _tail) {
        this.left = _head;
        this.right = _tail;
    }

    public ASTList(ASTree _head) {
        this.left = _head;
        this.right = null;
    }

    public static ASTList make(ASTree e1, ASTree e2, ASTree e3) {
        return new ASTList(e1, new ASTList(e2, new ASTList(e3)));
    }

    @Override // javassist.compiler.ast.ASTree
    public ASTree getLeft() {
        return this.left;
    }

    @Override // javassist.compiler.ast.ASTree
    public ASTree getRight() {
        return this.right;
    }

    @Override // javassist.compiler.ast.ASTree
    public void setLeft(ASTree _left) {
        this.left = _left;
    }

    @Override // javassist.compiler.ast.ASTree
    public void setRight(ASTree _right) {
        this.right = (ASTList) _right;
    }

    public ASTree head() {
        return this.left;
    }

    public void setHead(ASTree _head) {
        this.left = _head;
    }

    public ASTList tail() {
        return this.right;
    }

    public void setTail(ASTList _tail) {
        this.right = _tail;
    }

    @Override // javassist.compiler.ast.ASTree
    public void accept(Visitor v) throws CompileError {
        v.atASTList(this);
    }

    @Override // javassist.compiler.ast.ASTree
    public String toString() {
        StringBuffer sbuf = new StringBuffer();
        sbuf.append("(<");
        sbuf.append(getTag());
        sbuf.append('>');
        ASTList aSTList = this;
        while (true) {
            ASTList list = aSTList;
            if (list != null) {
                sbuf.append(' ');
                ASTree a = list.left;
                sbuf.append(a == null ? "<null>" : a.toString());
                aSTList = list.right;
            } else {
                sbuf.append(')');
                return sbuf.toString();
            }
        }
    }

    public int length() {
        return length(this);
    }

    public static int length(ASTList list) {
        if (list == null) {
            return 0;
        }
        int n = 0;
        while (list != null) {
            list = list.right;
            n++;
        }
        return n;
    }

    public ASTList sublist(int nth) {
        ASTList aSTList = this;
        while (true) {
            ASTList list = aSTList;
            int i = nth;
            nth--;
            if (i > 0) {
                aSTList = list.right;
            } else {
                return list;
            }
        }
    }

    public boolean subst(ASTree newObj, ASTree oldObj) {
        ASTList aSTList = this;
        while (true) {
            ASTList list = aSTList;
            if (list != null) {
                if (list.left != oldObj) {
                    aSTList = list.right;
                } else {
                    list.left = newObj;
                    return true;
                }
            } else {
                return false;
            }
        }
    }

    public static ASTList append(ASTList a, ASTree b) {
        return concat(a, new ASTList(b));
    }

    public static ASTList concat(ASTList a, ASTList b) {
        if (a == null) {
            return b;
        }
        ASTList aSTList = a;
        while (true) {
            ASTList list = aSTList;
            if (list.right != null) {
                aSTList = list.right;
            } else {
                list.right = b;
                return a;
            }
        }
    }
}