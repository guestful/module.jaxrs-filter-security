/**
 * Copyright (C) 2013 Guestful (info@guestful.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.guestful.jaxrs.security.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class Crypto {

    private static final int DEFAULT_ITERATIONS = 1;
    private static final char[] BASE16 = "0123456789abcdef".toCharArray();

    public static String toHexString(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = BASE16[v >>> 4];
            hexChars[j * 2 + 1] = BASE16[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String sha512(String password, String salt, int hashIterations) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
        if (salt != null) {
            digest.reset();
            digest.update(salt.getBytes(StandardCharsets.UTF_8));
        }
        byte[] data = password.getBytes(StandardCharsets.UTF_8);
        byte[] hashed = digest.digest(data);
        int iterations = hashIterations - DEFAULT_ITERATIONS; //already hashed once above
        for (int i = 0; i < iterations; i++) {
            digest.reset();
            hashed = digest.digest(hashed);
        }
        return toHexString(hashed);
    }

    public static String uuid() {
        UUID j = UUID.randomUUID();
        byte[] data = new byte[16];
        long msb = j.getMostSignificantBits();
        long lsb = j.getLeastSignificantBits();
        for (int i = 0; i < 8; i++) {
            data[i] = (byte) (msb & 0xff);
            msb >>>= 8;
        }
        for (int i = 8; i < 16; i++) {
            ;
            data[i] = (byte) (lsb & 0xff);
            lsb >>>= 8;
        }
        String str = Base64.getUrlEncoder().encodeToString(data);
        int pos = str.length() - 1;
        while (str.charAt(pos) == '=') {
            pos--;
        }
        return str.substring(0, pos + 1);
    }

    public static boolean isUuid(String uuidString) {
        try {
            if (uuidString == null) return false;
            byte[] b = Base64.getUrlDecoder().decode(uuidString);
            // the string is the B64 representation of 128bits: two long
            return b.length == 16;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

}
