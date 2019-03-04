package de.rheinwolf.iam.connid.connectors.passwd.util;

import org.identityconnectors.common.security.GuardedString;

/**
 * Accessor for GuardedString values.
 */
public class GuardedStringAccessor implements GuardedString.Accessor {
    private byte[] value = null;

    /**
     * Retrieving the value of a GuardedString as byte array.
     *
     * @param guardedString     The GuardedString whose value should be retrieved.
     *
     * @return Returns the value as byte array.
     */
    public static byte[] asByteArray(GuardedString guardedString) {
        if (guardedString == null)
            return null;

        GuardedStringAccessor accessor = new GuardedStringAccessor();

        guardedString.access(accessor);

        return accessor.value;
    }

    /**
     * Accessing the value of the GuardedString.
     *
     * @param chars         The value of the GuardedString as char array.
     */
    @Override
    public void access(char[] chars) {
        value = new byte[chars.length];

        for (int i = 0; i < chars.length; ++i)
            value[i] = (byte) chars[i];
    }
}
