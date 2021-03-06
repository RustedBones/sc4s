/*
 * Copyright 2021 Michel Davit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package xyz.gianlu.librespot.common;

import com.google.protobuf.ByteString;

import javax.sound.sampled.Mixer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.*;

/**
 * @author Gianlu
 */
public final class Utils {
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    private static final String randomString = "abcdefghijklmnopqrstuvwxyz0123456789";

    private Utils() {
    }


    public static String randomHexString(Random random, int length) {
        byte[] bytes = new byte[length / 2];
        random.nextBytes(bytes);
        return bytesToHex(bytes, 0, bytes.length, false, length);
    }


    public static String randomString(Random random, int length) {
        char[] chars = new char[length];
        for (int i = 0; i < length; i++)
            chars[i] = randomString.charAt(random.nextInt(randomString.length()));
        return new String(chars);
    }


    public static String truncateMiddle(String str, int length) {
        if (length <= 1) throw new IllegalStateException();

        int first = length / 2;
        String result = str.substring(0, first);
        result += "...";
        result += str.substring(str.length() - (length - first));
        return result;
    }


    public static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        boolean lastWasR = false;
        int read;
        while ((read = in.read()) != -1) {
            if (read == '\r') {
                lastWasR = true;
                continue;
            } else if (read == '\n' && lastWasR) {
                break;
            }

            buffer.write(read);
        }

        return buffer.toString();
    }

    public static void removeCryptographyRestrictions() {
        if (!isRestrictedCryptography()) {
            return;
        }

        /*
         * Do the following, but with reflection to bypass access checks:
         *
         * JceSecurity.isRestricted = false;
         * JceSecurity.defaultPolicy.perms.clear();
         * JceSecurity.defaultPolicy.add(CryptoAllPermission.INSTANCE);
         */

        try {
            Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
            Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
            isRestrictedField.setAccessible(true);
            Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(isRestrictedField, isRestrictedField.getModifiers() & ~Modifier.FINAL);
            isRestrictedField.set(null, false);

            Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");
            defaultPolicyField.setAccessible(true);
            PermissionCollection defaultPolicy = (PermissionCollection) defaultPolicyField.get(null);

            Class<?> cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
            Field perms = cryptoPermissions.getDeclaredField("perms");
            perms.setAccessible(true);
            ((Map<?, ?>) perms.get(defaultPolicy)).clear();

            Class<?> cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");
            Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");
            instance.setAccessible(true);
            defaultPolicy.add((Permission) instance.get(null));
        } catch (Exception ex) {
           ex.printStackTrace();
        }
    }

    private static boolean isRestrictedCryptography() {
        // This matches Oracle Java 7 and 8, but not Java 9 or OpenJDK.
        String name = System.getProperty("java.runtime.name");
        String ver = System.getProperty("java.version");
        return name != null && name.equals("Java(TM) SE Runtime Environment") && ver != null && (ver.startsWith("1.7") || ver.startsWith("1.8"));
    }


    public static String[] split(String str, char c) {
        if (str.isEmpty()) return new String[0];

        int size = 1;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == c) size++;
        }

        String tmp = str;
        String[] split = new String[size];
        for (int j = size - 1; j >= 0; j--) {
            int i = tmp.lastIndexOf(c);
            if (i == -1) {
                split[j] = tmp;
            } else {
                split[j] = tmp.substring(i + 1);
                tmp = tmp.substring(0, i);
            }
        }

        return split;
    }

    public static byte[] hexToBytes(String str) {
        int len = str.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
        return data;
    }


    public static byte[] toByteArray(BigInteger i) {
        byte[] array = i.toByteArray();
        if (array[0] == 0) array = Arrays.copyOfRange(array, 1, array.length);
        return array;
    }


    public static byte[] toByteArray(int i) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(i);
        return buffer.array();
    }


    public static String bytesToHex(ByteString bytes) {
        return bytesToHex(bytes.toByteArray());
    }


    public static String bytesToHex(byte[] bytes) {
        return bytesToHex(bytes, 0, bytes.length, false, -1);
    }


    public static String bytesToHex(byte[] bytes, int off, int len) {
        return bytesToHex(bytes, off, len, false, -1);
    }


    public static String bytesToHex(byte[] bytes, int offset, int length, boolean trim, int minLength) {
        if (bytes == null) return "";

        int newOffset = 0;
        boolean trimming = trim;
        char[] hexChars = new char[length * 2];
        for (int j = offset; j < length; j++) {
            int v = bytes[j] & 0xFF;
            if (trimming) {
                if (v == 0) {
                    newOffset = j + 1;

                    if (minLength != -1 && length - newOffset == minLength)
                        trimming = false;

                    continue;
                } else {
                    trimming = false;
                }
            }

            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }

        return new String(hexChars, newOffset * 2, hexChars.length - newOffset * 2);
    }

    public static String byteToHex(byte b) {
        char[] hexChars = new char[2];
        int v = b & 0xFF;
        hexChars[0] = hexArray[v >>> 4];
        hexChars[1] = hexArray[v & 0x0F];
        return new String(hexChars);
    }

    public static String mixersToString(List<Mixer> list) {
        StringBuilder builder = new StringBuilder();
        boolean first = true;
        for (Mixer mixer : list) {
            if (!first) builder.append(", ");
            first = false;

            builder.append('\'').append(mixer.getMixerInfo().getName()).append('\'');
        }

        return builder.toString();
    }


    public static String toBase64(ByteString bytes) {
        return Base64.getEncoder().encodeToString(bytes.toByteArray());
    }


    public static ByteString fromBase64(String str) {
        return ByteString.copyFrom(Base64.getDecoder().decode(str.getBytes()));
    }
}
