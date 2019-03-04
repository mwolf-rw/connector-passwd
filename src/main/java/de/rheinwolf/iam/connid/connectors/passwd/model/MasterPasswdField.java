package de.rheinwolf.iam.connid.connectors.passwd.model;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.OperationalAttributeInfos;

import static org.identityconnectors.framework.common.objects.AttributeInfo.Flags.REQUIRED;

/**
 * Enumeration of all fields in the account object class when using a master.passwd file.
 */
public enum MasterPasswdField implements SchemaUtil.SchemaField {
    ACCOUNT_EXPIRATION_TIME(OperationalAttributeInfos.DISABLE_DATE.getName(), "accountExpirationTime", Long.class, 6),
    COMMENT("comment", null, String.class, 7),
    GID("gid", null, Integer.class, 3, REQUIRED),
    HOME_DIRECTORY("homeDirectory", null, String.class, 8),
    LOGIN_CLASS("loginClass", null, String.class, 4),
    LOGIN_NAME(Name.NAME, "loginName", String.class, 0, REQUIRED),
    LOGIN_SHELL("loginShell", null, String.class, 9),
    PASSWORD(OperationalAttributeInfos.PASSWORD.getName(), "password", GuardedString.class, 1),
    PASSWORD_EXPIRATION_TIME(OperationalAttributeInfos.PASSWORD_EXPIRATION_DATE.getName(), "passwordExpirationTime", Long.class, 5),
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
    MasterPasswdField(String attributeName, String nativeName, Class<?> clazz, int offset, AttributeInfo.Flags... flags) {
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
