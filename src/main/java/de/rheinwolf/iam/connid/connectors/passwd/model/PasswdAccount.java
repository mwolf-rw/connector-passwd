package de.rheinwolf.iam.connid.connectors.passwd.model;

import de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration;

import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.SchemaBuilder;

import java.util.HashSet;
import java.util.Set;

/**
 * The account object class.
 */
public class PasswdAccount {
    /**
     * Retrieving the schema for the account object class.
     *
     * @param schemaBuilder     A schema builder instance where the schema will be stored.
     */
    public static void schema(PasswdConfiguration configuration, SchemaBuilder schemaBuilder) {
        ObjectClassInfoBuilder objectClassInfoBuilder = new ObjectClassInfoBuilder();
        String                 methodName             = configuration.getMethod();

        // Use the master.passwd fields on BSDs
        if ((PasswdConfiguration.METHOD_PW.equals(methodName)) || (methodName.endsWith(":" + PasswdConfiguration.SUBMETHOD_BSD))) {
            for (MasterPasswdField field : MasterPasswdField.values()) {
                SchemaUtil.buildAttributeInfo(objectClassInfoBuilder, field);
            }

        // Use the combined shadow and passwd on GNU/Linux
        } else {
            Set<String> attributeNames = new HashSet<>();

            for (ShadowField field : ShadowField.values()) {
                SchemaUtil.buildAttributeInfo(objectClassInfoBuilder, field);
                attributeNames.add(field.getAttributes().getAttributeName());
            }
            for (PasswdField field : PasswdField.values()) {
                if (!attributeNames.contains(field.getAttributes().getAttributeName()))
                    SchemaUtil.buildAttributeInfo(objectClassInfoBuilder, field);
            }
        }

        objectClassInfoBuilder.setType(ObjectClass.ACCOUNT_NAME);
        schemaBuilder.defineObjectClass(objectClassInfoBuilder.build());
    }
}
