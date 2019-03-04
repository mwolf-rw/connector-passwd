package de.rheinwolf.iam.connid.connectors.passwd.model;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.OperationalAttributeInfos;

import static org.identityconnectors.framework.common.objects.AttributeInfo.Flags.REQUIRED;
import static org.identityconnectors.framework.common.objects.OperationalAttributeInfos.DISABLE_DATE;

/**
 * Enumeration of all fields in the account object class when using a shadow file.
 */
public enum ShadowField implements SchemaUtil.SchemaField {
    LOGIN_NAME(Name.NAME, "loginName", String.class, 0, REQUIRED),
    PASSWORD(OperationalAttributeInfos.PASSWORD.getName(), "password", GuardedString.class, 1),
    LAST_PASSWORD_CHANGE("lastPasswordChange", null, Long.class, 2),
    MINIMUM_PASSWORD_AGE("minimumPasswordAge", null, Long.class, 3),
    MAXIMUM_PASSWORD_AGE("maximumPasswordAge", null, Long.class, 4),
    PASSWORD_WARNING_PERIOD("passwordWarningPeriod", null, Long.class, 5),
    PASSWORD_INACTIVITY_PERIOD("passwordInactivityPeriod", null, Long.class, 6),
    ACCOUNT_EXPIRATION_TIME(DISABLE_DATE.getName(), "accountExpirationTime", Long.class, 7);

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
    ShadowField(String attributeName, String nativeName, Class<?> clazz, int offset, AttributeInfo.Flags... flags) {
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
