package de.rheinwolf.iam.connid.connectors.passwd.model;

import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.SchemaBuilder;

import java.util.List;

/**
 * The group object class.
 */
public class PasswdGroup {
    /**
     * Retrieving the schema for the account object class.
     *
     * @param schemaBuilder     A schema builder instance where the schema will be stored.
     */
    public static void schema(SchemaBuilder schemaBuilder) {
        ObjectClassInfoBuilder objectClassInfoBuilder = new ObjectClassInfoBuilder();

        for (GroupField field : GroupField.values()) {
            SchemaUtil.buildAttributeInfo(objectClassInfoBuilder, field);
        }

        objectClassInfoBuilder.setType(ObjectClass.GROUP_NAME);
        schemaBuilder.defineObjectClass(objectClassInfoBuilder.build());
    }

    /**
     * Converting fields from a passwd file to a connector object.
     *
     * @param objectClass       The object class instance.
     * @param fields            The passwd fields.
     *
     * @return Returns a ConnectorObject, or null if the field information is incomplete.
     */
    public static ConnectorObject toConnectorObject(ObjectClass objectClass, List<String> fields) {
        return SchemaUtil.toConnectorObject(objectClass, GroupField.values(), fields);
    }
}
