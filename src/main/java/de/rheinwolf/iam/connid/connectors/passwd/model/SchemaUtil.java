package de.rheinwolf.iam.connid.connectors.passwd.model;

import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.AttributeInfo.Flags;

import java.util.*;

/**
 * Utility methods for populating the ConnID schema.
 */
public class SchemaUtil {
    /**
     * Enumeration describing a schema field.
     */
    public interface SchemaField {
        /**
         * Retrieving the attributes.
         */
        SchemaFieldAttributes getAttributes();
    }

    /**
     * Attributes of a schema field.
     */
    public static class SchemaFieldAttributes {
        private String                attributeName;
        private Class<?>              clazz;
        private AttributeInfo.Flags[] flags;
        private String                nativeName;
        private int                   offset;

        /**
         * Constructing the field.
         *
         * @param attributeName     The ConnID attribute name.
         * @param nativeName        The native attribute name or null.
         * @param clazz             The Java class for the attribute.
         * @param offset            The offset in the account passwd file.
         * @param flags             The flags for the attribute.
         */
        SchemaFieldAttributes(String attributeName, String nativeName, Class<?> clazz, int offset, AttributeInfo.Flags... flags) {
            this.attributeName = attributeName;
            this.clazz         = clazz;
            this.flags         = flags;
            this.nativeName    = nativeName;
            this.offset        = offset;
        }

        /**
         * Retrieving the ConnID attribute name.
         *
         * @return Returns the ConnID attribute name.
         */
        public String getAttributeName() {
            return attributeName;
        }

        /**
         * Retrieving the Java class for the attribute.
         *
         * @return Returns a Class instance.
         */
        Class<?> getClazz() {
            return clazz;
        }

        /**
         * Retrieving the flags for the attribute.
         *
         * @return Returns an array of AttributeInfo.Flags.
         */
        AttributeInfo.Flags[] getFlags() {
            return flags;
        }

        /**
         * Retrieving the native name for the attribute.
         *
         * @return Returns the native name for the attribute, or null
         *         if it is the same as the ConnID name.
         */
        String getNativeName() {
            return nativeName;
        }

        /**
         * Retrieving the offset of the attribute in the passwd file.
         *
         * @return Returns the offset in the passwd fields as integer.
         */
        int getOffset() {
            return offset;
        }
    }


    /**
     * Adding an attribute definition to the schema object.
     *
     * @param objectClassInfoBuilder        The object class info builder.
     * @param schemaField                   The schema field.
     */
    static void buildAttributeInfo(ObjectClassInfoBuilder objectClassInfoBuilder, SchemaField schemaField) {
        SchemaFieldAttributes attributes           = schemaField.getAttributes();
        AttributeInfoBuilder  attributeInfoBuilder = new AttributeInfoBuilder(attributes.getAttributeName(), attributes.getClazz());
        Set<Flags>            flagsSet             = new HashSet<>(attributes.getFlags().length);

        Collections.addAll(flagsSet, attributes.getFlags());
        attributeInfoBuilder.setFlags(flagsSet);

        if (attributes.getNativeName() != null)
            attributeInfoBuilder.setNativeName(attributes.getNativeName());

        if (OperationalAttributeInfos.PASSWORD.is(attributes.getAttributeName())) {
            attributeInfoBuilder.setReturnedByDefault(false);
            attributeInfoBuilder.setReadable(false);
        }

        objectClassInfoBuilder.addAttributeInfo(attributeInfoBuilder.build());

        if (attributes.getAttributeName().equals(Name.NAME)) {
            attributeInfoBuilder.setName(Uid.NAME);
            objectClassInfoBuilder.addAttributeInfo(attributeInfoBuilder.build());
        }
    }

    /**
     * Joining a connector object with another one from a source map.
     *
     * @param connectorObject       The connector object.
     * @param source                The source map.
     * @param keyAttributeName      The name of the attribute on which the merge should happen.
     *
     * @return Returns a ConnectorObject instance with attributes from both instances.
     */
    public static ConnectorObject join(ConnectorObject connectorObject, Map<String, ConnectorObject> source, String keyAttributeName) {
        if (connectorObject == null)
            return null;

        ConnectorObjectBuilder objectBuilder  = new ConnectorObjectBuilder();
        ConnectorObject        objectToMerge  = null;
        Set<String>            attributeNames = new HashSet<>();

        objectBuilder.setObjectClass(connectorObject.getObjectClass());

        for (Attribute attribute : connectorObject.getAttributes()) {
            objectBuilder.addAttribute(attribute);
            attributeNames.add(attribute.getName());

            if (attribute.is(keyAttributeName))
                objectToMerge = source.get(attribute.getValue().get(0).toString());
        }

        if (objectToMerge != null) {
            for (Attribute attribute : objectToMerge.getAttributes()) {
                if (!attributeNames.contains(attribute.getName()))
                    objectBuilder.addAttribute(attribute);
            }
        }

        return objectBuilder.build();
    }


    /**
     * Converting fields from a passwd file to a connector object.
     *
     * @param objectClass       The object class instance.
     * @param schemaFields      The schema fields for the object class.
     * @param fields            The passwd fields.
     *
     * @return Returns a ConnectorObject, or null if the field information is incomplete.
     */
    public static ConnectorObject toConnectorObject(ObjectClass objectClass, SchemaField[] schemaFields, List<String> fields) {
        ConnectorObjectBuilder objectBuilder = new ConnectorObjectBuilder();

        objectBuilder.setObjectClass(objectClass);

        for (SchemaField schemaField : schemaFields) {
            buildAttribute(objectBuilder, schemaField, fields);
        }

        return objectBuilder.build();
    }

    /**
     * Adding an attribute to a connector object.
     *
     * @param connectorObjectBuilder        The connector object builder.
     * @param schemaField                   The schema field.
     * @param values                        The input values.
     */
    private static void buildAttribute(ConnectorObjectBuilder connectorObjectBuilder, SchemaField schemaField, List<String> values) {
        SchemaFieldAttributes attributes = schemaField.getAttributes();

        if ((values.size() <= attributes.getOffset()) || (OperationalAttributeInfos.PASSWORD.is(attributes.getAttributeName())))
            return;

        String stringValue = values.get(attributes.getOffset()).trim();

        if (stringValue.isEmpty())
            return;

        AttributeBuilder attributeBuilder = new AttributeBuilder();

        if (Arrays.asList(attributes.getFlags()).contains(Flags.MULTIVALUED)) {
            String[] stringValues = stringValue.split(",");

            for (String mvStringValue : stringValues) {
                mvStringValue = mvStringValue.trim();

                if (mvStringValue.isEmpty())
                    continue;

                Object value = getAttributeValue(attributes.getClazz(), mvStringValue);

                if (value != null)
                    attributeBuilder.addValue(value);
            }
        } else {
            attributeBuilder.addValue(getAttributeValue(attributes.getClazz(), stringValue));
        }

        attributeBuilder.setName(attributes.getAttributeName());
        connectorObjectBuilder.addAttribute(attributeBuilder.build());
    }

    /**
     * Retrieving the attribute value for the given string value and target class.
     *
     * @param targetClass       The target class for the attribute.
     * @param stringValue       The string value.
     *
     * @return Returns the real value of the attribute.
     */
    private static Object getAttributeValue(Class<?> targetClass, String stringValue) {
        if (Long.class.equals(targetClass)) {
            Long result = Long.valueOf(stringValue);

            if (result.equals(0L))
                return null;

            return result;
        }

        if (Integer.class.equals(targetClass))
            return Integer.valueOf(stringValue);

        return stringValue;
    }
}
