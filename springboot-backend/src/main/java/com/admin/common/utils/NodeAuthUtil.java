package com.admin.common.utils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public final class NodeAuthUtil {
    public static final String HEADER_SECRET = "X-Flux-Node-Secret";
    public static final String HEADER_TIMESTAMP = "X-Flux-Timestamp";
    public static final String HEADER_NONCE = "X-Flux-Nonce";
    public static final String HEADER_SIGNATURE = "X-Flux-Signature";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final long MAX_SKEW_SECONDS = 300;

    private NodeAuthUtil() {}

    public static String secretFrom(HttpServletRequest request) {
        String secret = request.getHeader(HEADER_SECRET);
        if (secret == null || secret.isBlank()) {
            // Legacy fallback kept only for compatibility during rolling upgrades.
            secret = request.getParameter("secret");
        }
        return secret;
    }

    public static boolean verify(HttpServletRequest request, String body, String secret) {
        if (secret == null || secret.isBlank()) return false;
        String timestamp = request.getHeader(HEADER_TIMESTAMP);
        String nonce = request.getHeader(HEADER_NONCE);
        String signature = request.getHeader(HEADER_SIGNATURE);
        if (timestamp == null || nonce == null || signature == null) {
            // Legacy query-secret requests are explicitly rejected unless the operator
            // opts in while upgrading old nodes.
            return Boolean.parseBoolean(System.getenv().getOrDefault("ALLOW_LEGACY_NODE_SECRET_QUERY", "false"))
                    && secret.equals(request.getParameter("secret"));
        }
        try {
            long ts = Long.parseLong(timestamp);
            long now = System.currentTimeMillis() / 1000L;
            if (Math.abs(now - ts) > MAX_SKEW_SECONDS) return false;
            String expected = sign(secret, request.getMethod(), request.getRequestURI(), timestamp, nonce, body == null ? "" : body);
            return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), signature.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    public static String sign(String secret, String method, String path, String timestamp, String nonce, String body) throws Exception {
        String canonical = method.toUpperCase() + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + sha256Hex(body == null ? "" : body);
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
        return Base64.getEncoder().encodeToString(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
    }

    private static String sha256Hex(String body) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(body.getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder(digest.length * 2);
        for (byte b : digest) hex.append(String.format("%02x", b));
        return hex.toString();
    }
}
