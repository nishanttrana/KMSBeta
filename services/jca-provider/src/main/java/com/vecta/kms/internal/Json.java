package com.vecta.kms.internal;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Minimal JSON for the ekm API: string-valued request objects, full parsing of responses. */
final class Json {

    private final String s;
    private int i;

    private Json(String s) {
        this.s = s;
    }

    static String object(Map<String, String> fields) {
        StringBuilder b = new StringBuilder("{");
        for (Map.Entry<String, String> e : fields.entrySet()) {
            if (b.length() > 1) {
                b.append(',');
            }
            quote(b, e.getKey()).append(':');
            quote(b, e.getValue());
        }
        return b.append('}').toString();
    }

    static Map<String, Object> parseObject(String text) {
        Json p = new Json(text == null ? "" : text);
        p.ws();
        if (p.i >= p.s.length() || p.s.charAt(p.i) != '{') {
            return new LinkedHashMap<>();
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> out = (Map<String, Object>) p.value();
        return out;
    }

    private static StringBuilder quote(StringBuilder b, String v) {
        b.append('"');
        for (char c : v.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        return b.append('"');
    }

    private Object value() {
        ws();
        char c = peek();
        switch (c) {
            case '{': {
                i++;
                Map<String, Object> m = new LinkedHashMap<>();
                ws();
                if (peek() == '}') {
                    i++;
                    return m;
                }
                while (true) {
                    ws();
                    String k = string();
                    ws();
                    expect(':');
                    m.put(k, value());
                    ws();
                    if (peek() == ',') {
                        i++;
                        continue;
                    }
                    expect('}');
                    return m;
                }
            }
            case '[': {
                i++;
                List<Object> l = new ArrayList<>();
                ws();
                if (peek() == ']') {
                    i++;
                    return l;
                }
                while (true) {
                    l.add(value());
                    ws();
                    if (peek() == ',') {
                        i++;
                        continue;
                    }
                    expect(']');
                    return l;
                }
            }
            case '"':
                return string();
            default:
                int start = i;
                while (i < s.length() && ",}] \t\r\n".indexOf(s.charAt(i)) < 0) {
                    i++;
                }
                String lit = s.substring(start, i);
                switch (lit) {
                    case "true": return Boolean.TRUE;
                    case "false": return Boolean.FALSE;
                    case "null": return null;
                    default:
                        try {
                            return Double.valueOf(lit);
                        } catch (NumberFormatException e) {
                            throw new IllegalArgumentException("invalid JSON at " + start);
                        }
                }
        }
    }

    private String string() {
        expect('"');
        StringBuilder b = new StringBuilder();
        while (true) {
            char c = s.charAt(i++);
            if (c == '"') {
                return b.toString();
            }
            if (c != '\\') {
                b.append(c);
                continue;
            }
            char e = s.charAt(i++);
            switch (e) {
                case 'n' -> b.append('\n');
                case 'r' -> b.append('\r');
                case 't' -> b.append('\t');
                case 'b' -> b.append('\b');
                case 'f' -> b.append('\f');
                case 'u' -> {
                    b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    i += 4;
                }
                default -> b.append(e);
            }
        }
    }

    private void ws() {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
    }

    private char peek() {
        if (i >= s.length()) {
            throw new IllegalArgumentException("unexpected end of JSON");
        }
        return s.charAt(i);
    }

    private void expect(char c) {
        if (peek() != c) {
            throw new IllegalArgumentException("expected '" + c + "' at " + i);
        }
        i++;
    }
}
