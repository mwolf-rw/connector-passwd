package de.rheinwolf.iam.connid.connectors.passwd.model;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.OperationalAttributeInfos;

import static org.identityconnectors.framework.common.objects.AttributeInfo.Flags.REQUIRED;

/**
 * Enumeration of all fields in the account object class when using a passwd file.
 */
public enum PasswdField implements SchemaUtil.SchemaField {
    COMMENT("comment", null, String.class, 4),
    GID("gid", null, Integer.class, 3, REQUIRED),
    HOME_DIRECTORY("homeDirectory", null, String.class, 5),
    LOGIN_NAME(Name.NAME, "loginName", String.class, 0, REQUIRED),
    LOGIN_SHELL("loginShell", null, String.class, 6),
    PASSWORD(OperationalAttributeInfos.PASSWORD.getName(), "password", GuardedString.class, 1),
    UID("uid", null, String.class, 2, REQUIRED);

    private SchemaUtil.SchemaFieldAttributes attributes;

    /**
     * Constructing the field.
     *
     * @param attributeName The ConnID attribute name.
     * @param nativeName    The native attribute name or null.
     * @param clazz         The Java class for the attribute.
     * @param offset        The offset in the account passwd file.
     * @param flags         The flags for the attribute.
     */
    PasswdField(String attributeName, String nativeName, Class<?> clazz, int offset, AttributeInfo.Flags... flags) {
        this.attributes = new SchemaUtil.SchemaFieldAttributes(attributeName, nativeName, clazz, offset, flags);
    }

    /**
     * Retrieving the attributes.
     */
    @Override
    public SchemaUtil.SchemaFieldAttributes getAttributes() {
        return attributes;
    }
}
