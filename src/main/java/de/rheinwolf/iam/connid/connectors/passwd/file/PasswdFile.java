package de.rheinwolf.iam.connid.connectors.passwd.file;

import de.rheinwolf.iam.connid.connectors.passwd.model.PasswdGroup;
import de.rheinwolf.iam.connid.connectors.passwd.model.SchemaUtil;

import org.identityconnectors.framework.common.exceptions.ConnectionBrokenException;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ObjectClass;

import java.util.Arrays;
import java.util.List;

/**
 * Utility methods for the passwd files.
 */
public class PasswdFile {
    /**
     * Converting a passwd entry to a connector object.
     *
     * @param objectClass       The object class.
     * @param input             The input line.
     * @param schemaFieldHint   The hint which schema fields should be used for accounts.
     *
     * @return Returns a ConnectorObject instance.
     */
    public static ConnectorObject toConnectorObject(ObjectClass objectClass, String input, SchemaUtil.SchemaField[] schemaFieldHint) {
        String trimmedInput = input.trim();

        if ((trimmedInput.isEmpty()) || (trimmedInput.startsWith("#")))
            return null;

        List<String> fields = Arrays.asList(input.split(":"));

        if (objectClass.is(ObjectClass.ACCOUNT_NAME))
            return SchemaUtil.toConnectorObject(objectClass, schemaFieldHint, fields);

        if (objectClass.is(ObjectClass.GROUP_NAME))
            return PasswdGroup.toConnectorObject(objectClass, fields);

        throw new ConnectionBrokenException("Invalid object class: " + objectClass);
    }
}
