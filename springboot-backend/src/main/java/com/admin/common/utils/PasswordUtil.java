package com.admin.common.utils;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Password hashing helper. New passwords use BCrypt; legacy MD5 hashes are
 * still accepted only to allow in-place migration on the next successful login.
 */
public final class PasswordUtil {
    private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder(12);

    private PasswordUtil() {}

    public static String hash(String rawPassword) {
        return ENCODER.encode(rawPassword);
    }

    public static boolean matches(String rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null) return false;
        if (storedHash.startsWith("$2a$") || storedHash.startsWith("$2b$") || storedHash.startsWith("$2y$")) {
            return ENCODER.matches(rawPassword, storedHash);
        }
        // Backward compatibility for existing installations; callers should
        // rehash after a successful legacy match.
        return storedHash.equals(Md5Util.md5(rawPassword));
    }

    public static boolean needsRehash(String storedHash) {
        return storedHash == null || !(storedHash.startsWith("$2a$") || storedHash.startsWith("$2b$") || storedHash.startsWith("$2y$"));
    }
}
