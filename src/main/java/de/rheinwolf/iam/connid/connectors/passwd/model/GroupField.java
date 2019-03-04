package de.rheinwolf.iam.connid.connectors.passwd.model;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.OperationalAttributeInfos;

import static org.identityconnectors.framework.common.objects.AttributeInfo.Flags.MULTIVALUED;
import static org.identityconnectors.framework.common.objects.AttributeInfo.Flags.REQUIRED;

/**
 * Enumeration of all fields in the group object class.
 */
public enum GroupField implements SchemaUtil.SchemaField {
    GID("gid", null, String.class, 2, REQUIRED),
    GROUP_NAME(Name.NAME, "groupName", String.class, 0, REQUIRED),
    MEMBERS("members", null, String.class, 3, MULTIVALUED),
    PASSWORD(OperationalAttributeInfos.PASSWORD.getName(), "password", GuardedString.class, 1);

    private final SchemaUtil.SchemaFieldAttributes attributes;

    /**
     * Constructing the field.
     *
     * @param attributeName     The ConnID attribute name.
     * @param nativeName        The native attribute name or null.
     * @param clazz             The Java class for the attribute.
     * @param offset            The offset in the account passwd file.
     * @param flags             The flags for the attribute.
     */
    GroupField(String attributeName, String nativeName, Class<?> clazz, int offset, AttributeInfo.Flags... flags) {
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
