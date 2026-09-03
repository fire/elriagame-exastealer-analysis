import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.util.*;

public class DumpTables {
    static String jsonEsc(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);
            if (c == '"') b.append("\\\"");
            else if (c == '\\') b.append("\\\\");
            else if (c >= 0x20 && c < 0x7f) b.append((char)c);
            else b.append(String.format("\\u%04x", c));
        }
        return b.toString();
    }
    public static void main(String[] a) throws Exception {
        File jar = new File(a[0]);
        String pkg = "com/xc17edb19a/";
        java.util.jar.JarFile jf = new java.util.jar.JarFile(jar);
        List<String> classes = new ArrayList<>();
        for (java.util.Enumeration<java.util.jar.JarEntry> e = jf.entries(); e.hasMoreElements(); ) {
            String n = e.nextElement().getName();
            if (n.startsWith(pkg) && n.endsWith(".class"))
                classes.add(n.substring(0, n.length()-6).replace('/', '.'));
        }
        Collections.sort(classes);
        URLClassLoader cl = new URLClassLoader(new URL[]{ jar.toURI().toURL() }, ClassLoader.getSystemClassLoader());
        PrintWriter out = new PrintWriter(new FileWriter(a[1]));
        out.println("{");
        boolean first = true;
        for (String cn : classes) {
            Map<String, String[]> sfields = new LinkedHashMap<>();
            Map<String, int[]> ifields = new LinkedHashMap<>();
            try {
                Class<?> c = Class.forName(cn, true, cl);
                for (Field f : c.getDeclaredFields()) {
                    if (!java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
                    f.setAccessible(true);
                    String tn = f.getType().getName();
                    try {
                        if (tn.equals("[Ljava.lang.String;")) sfields.put(f.getName(), (String[])f.get(null));
                        else if (tn.equals("[I"))               ifields.put(f.getName(), (int[])f.get(null));
                    } catch (Throwable t) {}
                }
            } catch (Throwable t) { System.err.println("skip " + cn + ": " + t); continue; }
            if (sfields.isEmpty() && ifields.isEmpty()) continue;
            if (!first) out.println(","); first = false;
            out.print("  \"" + cn + "\": {");
            out.print(" \"strings\": {");
            boolean fs = true;
            for (var e : sfields.entrySet()) {
                if (!fs) out.print(","); fs = false;
                out.print(" \"" + e.getKey() + "\": [");
                String[] arr = e.getValue();
                for (int i = 0; i < arr.length; i++) {
                    if (i > 0) out.print(",");
                    out.print("\"" + jsonEsc(arr[i]) + "\"");
                }
                out.print("]");
            }
            out.print(" }, \"ints\": {");
            fs = true;
            for (var e : ifields.entrySet()) {
                if (!fs) out.print(","); fs = false;
                out.print(" \"" + e.getKey() + "\": [");
                int[] arr = e.getValue();
                for (int i = 0; i < arr.length; i++) {
                    if (i > 0) out.print(",");
                    out.print(arr[i]);
                }
                out.print("]");
            }
            out.print(" } }");
        }
        out.println(); out.println("}");
        out.close();
    }
}
