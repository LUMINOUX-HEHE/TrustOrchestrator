import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Trust Orchestrator REST client — JDK stdlib only (java.net.http).
 *
 * <pre>
 * ToClient c = new ToClient("http://localhost:8080", "admin-token");
 * c.createOrg("acme", "");
 * c.issue("acme", "c1", "user", "c0");
 * System.out.println(c.state("acme"));
 * </pre>
 *
 * Smoke check:  java ToClient.java http://localhost:8080 <token>
 */
public class ToClient {
    private final String base;
    private final String token;
    private final HttpClient hc = HttpClient.newHttpClient();

    public ToClient(String base, String token) {
        this.base = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        this.token = token;
    }

    /** Thrown for any non-2xx response; carries the gateway error body. */
    public static class TOError extends RuntimeException {
        public final int status;

        public TOError(int status, String body) {
            super("gateway: " + status + " " + body);
            this.status = status;
        }
    }

    private String req(String method, String path, String jsonBody) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .timeout(java.time.Duration.ofSeconds(30));
        if (jsonBody != null) {
            b.method(method, HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8));
        } else {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        }
        try {
            HttpResponse<String> r = hc.send(b.build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() >= 400) {
                throw new TOError(r.statusCode(), r.body());
            }
            return r.body();
        } catch (TOError e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> json(String method, String path, String body) {
        String s = req(method, path, body);
        try {
            return (Map<String, Object>) parse(s);
        } catch (Exception e) {
            throw new RuntimeException("bad JSON from gateway: " + s, e);
        }
    }

    /** Minimal JSON parser: objects/arrays/strings/numbers/booleans. */
    private static Object parse(String s) {
        return new Parser(s).value();
    }

    private static final class Parser {
        private final String s;
        private int i;

        Parser(String s) { this.s = s; }

        Object value() {
            skipWs();
            char c = s.charAt(i);
            if (c == '{') return object();
            if (c == '[') return array();
            if (c == '"') return string();
            if (c == 't') { i += 4; return Boolean.TRUE; }
            if (c == 'f') { i += 5; return Boolean.FALSE; }
            if (c == 'n') { i += 4; return null; }
            return number();
        }

        private void skipWs() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }

        private Map<String, Object> object() {
            Map<String, Object> m = new java.util.LinkedHashMap<>();
            i++; skipWs();
            if (s.charAt(i) == '}') { i++; return m; }
            while (true) {
                skipWs();
                String k = string();
                skipWs(); i++; // :
                skipWs();
                m.put(k, value());
                skipWs();
                char c = s.charAt(i++);
                if (c == '}') return m;
                if (c != ',') throw new IllegalArgumentException("expected , or }");
            }
        }

        private List<Object> array() {
            List<Object> l = new ArrayList<>();
            i++; skipWs();
            if (s.charAt(i) == ']') { i++; return l; }
            while (true) {
                skipWs();
                l.add(value());
                skipWs();
                char c = s.charAt(i++);
                if (c == ']') return l;
                if (c != ',') throw new IllegalArgumentException("expected , or ]");
            }
        }

        private String string() {
            i++; // opening quote
            StringBuilder b = new StringBuilder();
            while (s.charAt(i) != '"') {
                char c = s.charAt(i++);
                if (c == '\\') {
                    c = s.charAt(i++);
                    if (c == 'n') b.append('\n');
                    else if (c == 't') b.append('\t');
                    else if (c == 'r') b.append('\r');
                    else if (c == 'u') { b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; }
                    else b.append(c);
                } else b.append(c);
            }
            i++; // closing quote
            return b.toString();
        }

        private Object number() {
            int start = i;
            while (i < s.length() && (Character.isDigit(s.charAt(i)) || s.charAt(i) == '-' || s.charAt(i) == '.' || s.charAt(i) == 'e' || s.charAt(i) == 'E' || s.charAt(i) == '+')) i++;
            String n = s.substring(start, i);
            return n.contains(".") || n.contains("e") || n.contains("E") ? Double.parseDouble(n) : Long.parseLong(n);
        }
    }

    private static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    // ---- orgs
    public List<Map<String, Object>> orgs() {
        return (List<Map<String, Object>>) json("GET", "/v1/orgs", null).get("orgs");
    }

    public Map<String, Object> createOrg(String name, String id) {
        return json("POST", "/v1/orgs", "{\"name\":\"" + esc(name) + "\",\"id\":\"" + esc(id) + "\"}");
    }

    public void deleteOrg(String org) {
        json("DELETE", "/v1/orgs/" + org, null);
    }

    // ---- trust events
    public String issue(String org, String certId, String identity, String via) {
        return String.valueOf(json("POST", "/v1/orgs/" + org + "/issue",
                "{\"cert_id\":\"" + esc(certId) + "\",\"identity\":\"" + esc(identity)
                        + "\",\"via\":\"" + esc(via) + "\"}").get("hash"));
    }

    public String revoke(String org, String certId) {
        return String.valueOf(json("POST", "/v1/orgs/" + org + "/revoke",
                "{\"cert_id\":\"" + esc(certId) + "\"}").get("hash"));
    }

    public Map<String, Object> state(String org) {
        return json("GET", "/v1/orgs/" + org + "/state", null);
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> timeline(String org, int limit) {
        return (List<Map<String, Object>>) json("GET", "/v1/orgs/" + org + "/timeline?limit=" + limit, null)
                .get("events");
    }

    // ---- detection + recovery
    public void scores(String org, String nodeId, double score, int badIndex) {
        String ev = badIndex >= 0 ? "{\"bad_index\":" + badIndex + "}" : "null";
        json("POST", "/v1/orgs/" + org + "/scores",
                "{\"node_id\":\"" + esc(nodeId) + "\",\"score\":" + score + ",\"p_value\":0.01,\"evidence\":" + ev + "}");
    }

    /** Recover with a shards JSON array, e.g. from `to shard` output:
     *  "[{\"x\":1,\"y\":\"...\",\"len\":32}, ...]" (at least 3 shards). */
    public Map<String, Object> recover(String org, String shardsJson) {
        return json("POST", "/v1/orgs/" + org + "/recover", "{\"shards\":" + shardsJson + "}");
    }

    // ---- audit + metrics + backup
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> audit(String org, String type, String identity, String cert, int limit) {
        StringBuilder q = new StringBuilder("?limit=").append(limit);
        if (!org.isEmpty()) q.append("&org=").append(org);
        if (!type.isEmpty()) q.append("&type=").append(type);
        if (!identity.isEmpty()) q.append("&identity=").append(identity);
        if (!cert.isEmpty()) q.append("&cert=").append(cert);
        return (List<Map<String, Object>>) json("GET", "/v1/audit" + q, null).get("events");
    }

    public String metrics() {
        return req("GET", "/v1/metrics", null);
    }

    public String backup() {
        return String.valueOf(json("POST", "/v1/backup", null).get("id"));
    }

    public byte[] downloadBackup(String id) {
        String s = req("GET", "/v1/backup/" + id + "/download", null);
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public void restore(byte[] bundle) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + "/v1/restore"))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(bundle));
        try {
            HttpResponse<String> r = hc.send(b.build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() >= 400) throw new TOError(r.statusCode(), r.body());
        } catch (TOError e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ---- users + webhooks
    public Map<String, Object> createUser(String id, String role, List<String> orgs) {
        StringBuilder o = new StringBuilder("[");
        for (int j = 0; j < orgs.size(); j++) {
            if (j > 0) o.append(',');
            o.append('"').append(esc(orgs.get(j))).append('"');
        }
        o.append(']');
        return json("POST", "/v1/users",
                "{\"id\":\"" + esc(id) + "\",\"role\":\"" + esc(role) + "\",\"orgs\":" + o + "}");
    }

    public List<Map<String, Object>> users() {
        return (List<Map<String, Object>>) json("GET", "/v1/users", null).get("users");
    }

    public void createWebhook(String url, String secret, List<String> events) {
        StringBuilder e = new StringBuilder("[");
        for (int j = 0; j < events.size(); j++) {
            if (j > 0) e.append(',');
            e.append('"').append(esc(events.get(j))).append('"');
        }
        e.append(']');
        json("POST", "/v1/webhooks",
                "{\"url\":\"" + esc(url) + "\",\"secret\":\"" + esc(secret) + "\",\"events\":" + e + "}");
    }

    public List<Map<String, Object>> webhooks() {
        return (List<Map<String, Object>>) json("GET", "/v1/webhooks", null).get("webhooks");
    }

    public void deleteWebhook(String id) {
        json("DELETE", "/v1/webhooks/" + id, null);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: java ToClient.java <base-url> <token>");
            System.exit(1);
        }
        ToClient c = new ToClient(args[0], args[1]);
        System.out.println("orgs: " + c.orgs());
        System.out.println(c.metrics().lines().limit(5).reduce((a, b) -> a + "\n" + b).orElse(""));
    }
}
