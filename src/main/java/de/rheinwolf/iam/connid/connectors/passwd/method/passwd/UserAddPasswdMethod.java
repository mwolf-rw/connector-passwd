package de.rheinwolf.iam.connid.connectors.passwd.method.passwd;

import de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration;
import de.rheinwolf.iam.connid.connectors.passwd.PasswdQuery;
import de.rheinwolf.iam.connid.connectors.passwd.connection.Connection;
import de.rheinwolf.iam.connid.connectors.passwd.file.PasswdFile;
import de.rheinwolf.iam.connid.connectors.passwd.method.become.BecomeMethod;
import de.rheinwolf.iam.connid.connectors.passwd.model.MasterPasswdField;
import de.rheinwolf.iam.connid.connectors.passwd.model.PasswdField;
import de.rheinwolf.iam.connid.connectors.passwd.model.SchemaUtil;
import de.rheinwolf.iam.connid.connectors.passwd.model.ShadowField;

import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.objects.*;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class UserAddPasswdMethod extends AbstractPasswdMethod {
    private static final String COMMAND_CAT     = "cat";
    private static final String COMMAND_USERADD = "useradd";
    private static final String COMMAND_WHEREIS = "whereis";

    private static final String FILE_GROUP        = "/etc/group";
    private static final String FILE_PASSWD       = "/etc/passwd";
    private static final String FILE_MASTERPASSWD = "/etc/master.passwd";
    private static final String FILE_SHADOW       = "/etc/shadow";

    private String masterPasswdFile = null;

    /**
     * Creating a new object.
     *
     * @param objectClass       The object class.
     * @param attributes        The attributes for the object.
     *
     * @return Returns the UID of the new object.
     */
    @Override
    public Uid create(ObjectClass objectClass, Set<Attribute> attributes) {
        return null;
    }

    /**
     * Deleting an object.
     *
     * @param objectClass       The object class.
     * @param uid               The UID of the object.
     */
    @Override
    public void delete(ObjectClass objectClass, Uid uid) {

    }

    /**
     * Initializing the method instance.
     *
     * @param connection        The current target system connection.
     * @param configuration     The current configuration.
     * @param becomeMethod      The current become method.
     */
    @Override
    public void init(Connection connection, PasswdConfiguration configuration, BecomeMethod becomeMethod) {
        String methodName = configuration.getMethod();

        super.init(connection, configuration, becomeMethod);

        if (methodName.endsWith(":" + PasswdConfiguration.SUBMETHOD_BSD)) {
            masterPasswdFile = FILE_MASTERPASSWD;
        } else if (methodName.endsWith(":" + PasswdConfiguration.SUBMETHOD_LINUX)) {
            masterPasswdFile = FILE_SHADOW;
        } else {
            throw new ConnectionFailedException("Unknown sub method in " + methodName);
        }
    }

    /**
     * Updating an object.
     *
     * @param objectClass       The object class.
     * @param uid               The UID of the object.
     * @param attributes        The changed attributes.
     *
     * @return Returns the (possibly changed) UID of the object.
     */
    @Override
    public Uid update(ObjectClass objectClass, Uid uid, Set<AttributeDelta> attributes) {
        return null;
    }

    /**
     * Searching for objects.
     *
     * @param objectClass       The object class.
     * @param query             The search filter.
     *
     * @return Returns a list of ConnectorObject instances.
     */
    @Override
    public List<ConnectorObject> search(ObjectClass objectClass, PasswdQuery query) {
        // Read the file in a single go if we have master.passwd or group file
        if ((objectClass.is(ObjectClass.GROUP_NAME)) || (FILE_MASTERPASSWD.equals(masterPasswdFile))) {
            String fileName = masterPasswdFile;

            if (objectClass.is(ObjectClass.GROUP_NAME))
                fileName = FILE_GROUP;

            return becomeMethod.execute(connection, null, COMMAND_CAT, fileName)
                    .expect(0)
                    .expectStdErrIsEmpty()
                    .getStdOut()
                    .stream()
                    .map(line -> PasswdFile.toConnectorObject(objectClass, line, MasterPasswdField.values()))
                    .filter(Objects::nonNull)
                    .filter(query::matches)
                    .collect(Collectors.toList());
        }

        // Merge passwd and shadow for account details on GNU/Linux
        Map<String, ConnectorObject> shadowObjects = becomeMethod.execute(connection, null, COMMAND_CAT, FILE_PASSWD)
                .expect(0)
                .expectStdErrIsEmpty()
                .getStdOut()
                .stream()
                .map(line -> PasswdFile.toConnectorObject(objectClass, line, ShadowField.values()))
                .filter(Objects::nonNull)
                .filter(query::matches)
                .collect(Collectors.toMap(
                        connectorObject -> connectorObject.getUid().getUidValue(),
                        connectorObject -> connectorObject
                ));

        return becomeMethod.execute(connection, null, COMMAND_CAT, FILE_PASSWD)
                .expect(0)
                .expectStdErrIsEmpty()
                .getStdOut()
                .stream()
                .map(line -> SchemaUtil.join(
                        PasswdFile.toConnectorObject(objectClass, line, PasswdField.values()),
                        shadowObjects,
                        Name.NAME))
                .filter(Objects::nonNull)
                .filter(query::matches)
                .collect(Collectors.toList());
    }

    /**
     * Testing the connection and method.
     */
    @Override
    public void test() {
        becomeMethod.execute(connection, null, COMMAND_WHEREIS, COMMAND_USERADD)
                .expect(0)
                .expectStdErrIsEmpty();
    }
}
