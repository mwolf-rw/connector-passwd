package de.rheinwolf.iam.connid.connectors.passwd.method.passwd;

import de.rheinwolf.iam.connid.connectors.passwd.PasswdQuery;

import org.identityconnectors.framework.common.objects.*;

import java.util.List;
import java.util.Set;

/**
 * Interface for different tools for manipulating passwd databases.
 */
public interface PasswdMethod {
    /**
     * Creating a new object.
     *
     * @param objectClass       The object class.
     * @param attributes        The attributes for the object.
     *
     * @return Returns the UID of the new object.
     */
    Uid create(ObjectClass objectClass, Set<Attribute> attributes);

    /**
     * Deleting an object.
     *
     * @param objectClass       The object class.
     * @param uid               The UID of the object.
     */
    void delete(ObjectClass objectClass, Uid uid);

    /**
     * Updating an object.
     *
     * @param objectClass       The object class.
     * @param uid               The UID of the object.
     * @param attributes        The changed attributes.
     *
     * @return Returns the (possibly changed) UID of the object.
     */
    Uid update(ObjectClass objectClass, Uid uid, Set<AttributeDelta> attributes);

    /**
     * Searching for objects.
     *
     * @param objectClass       The object class.
     * @param query             The search filter.
     *
     * @return Returns a list of ConnectorObject instances.
     */
    List<ConnectorObject> search(ObjectClass objectClass, PasswdQuery query);

    /**
     * Testing the connection and method.
     */
    void test();
}
