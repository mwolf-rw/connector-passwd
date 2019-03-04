package de.rheinwolf.iam.connid.connectors.passwd;

import de.rheinwolf.iam.connid.connectors.passwd.connection.Connection;
import de.rheinwolf.iam.connid.connectors.passwd.connection.ConnectionFactory;
import de.rheinwolf.iam.connid.connectors.passwd.method.passwd.PasswdMethod;
import de.rheinwolf.iam.connid.connectors.passwd.method.MethodFactory;
import de.rheinwolf.iam.connid.connectors.passwd.model.PasswdAccount;
import de.rheinwolf.iam.connid.connectors.passwd.model.PasswdGroup;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.PoolableConnector;
import org.identityconnectors.framework.spi.operations.*;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * The main passwd connector implementation class.
 */
@ConnectorClass(configurationClass = PasswdConfiguration.class, displayNameKey = "passwd.connector.display")
public class PasswdConnector implements
        AuthenticateOp,
        CreateOp,
        DeleteOp,
        PoolableConnector,
        SchemaOp,
        ScriptOnResourceOp,
        SearchOp<PasswdQuery>,
        TestOp,
        UpdateAttributeValuesOp,
        UpdateDeltaOp {
    private PasswdConfiguration configuration;
    private Connection          connection;
    private PasswdMethod        method;

    /**
     * Adding attribute values to an existing object.
     *
     * @param objectClass           The object class.
     * @param uid                   The UID of the object.
     * @param attributes            The attributes that should be added.
     * @param operationOptions      The operation options.
     *
     * @return Returns the (possibly new) UID of the object.
     */
    @Override
    public Uid addAttributeValues(ObjectClass objectClass, Uid uid, Set<Attribute> attributes, OperationOptions operationOptions) {
        Set<AttributeDelta> attributeDeltas = new HashSet<>(attributes.size());

        for (Attribute attribute : attributes) {
            attributeDeltas.add(AttributeDeltaBuilder.build(
                    attribute.getName(),
                    attribute.getValue(),
                    Collections.emptySet()
            ));
        }

        return method.update(objectClass, uid, attributeDeltas);
    }

    /**
     * Trying to authenticate to the target system given username and password.
     *
     * @param objectClass           The object class for authentication.
     * @param username              The login name.
     * @param password              The password.
     * @param operationOptions      The operation options.
     *
     * @return Returns the UID that was used to authenticate.
     */
    @Override
    public Uid authenticate(ObjectClass objectClass, String username, GuardedString password, OperationOptions operationOptions) {
        if (!objectClass.is(ObjectClass.ACCOUNT_NAME))
            throw new ConnectionFailedException("Invalid object class " + objectClass.getObjectClassValue());

        connection.authenticate(username, password);

        return new Uid(username);
    }

    /**
     * Checking whether the connection is still alive.
     */
    @Override
    public void checkAlive() {
        if (!connection.isAlive())
            throw new ConnectionFailedException();
    }

    /**
     * Creating a new object on the resource.
     *
     * @param objectClass           The object class.
     * @param attributes            The attributes for the object.
     * @param operationOptions      The operation options.
     *
     * @return Returns the UID of the new object.
     */
    @Override
    public Uid create(ObjectClass objectClass, Set<Attribute> attributes, OperationOptions operationOptions) {
        return method.create(objectClass, attributes);
    }

    /**
     * Creating a filter translator instance.
     *
     * @param objectClass           The object class on which the filter should be applied.
     * @param operationOptions      Options for the operation.
     *
     * @return Returns a FilterTranslator instance.
     */
    @Override
    public FilterTranslator<PasswdQuery> createFilterTranslator(ObjectClass objectClass, OperationOptions operationOptions) {
        return new PasswdFilterTranslator();
    }

    /**
     * Deleting an object from the resource.
     *
     * @param objectClass           The object class.
     * @param uid                   The UID of the object that should be deleted.
     * @param operationOptions      The operation options.
     */
    @Override
    public void delete(ObjectClass objectClass, Uid uid, OperationOptions operationOptions) {
        method.delete(objectClass, uid);
    }

    /**
     * Disposing the connector.
     */
    @Override
    public void dispose() {
        connection.close();
    }

    /**
     * Executing a search query.
     *
     * @param objectClass           The object class that is searched.
     * @param query                 The search filter.
     * @param resultsHandler        The result handler.
     * @param operationOptions      Options for the search operation.
     */
    @Override
    public void executeQuery(ObjectClass objectClass, PasswdQuery query, ResultsHandler resultsHandler, OperationOptions operationOptions) {
        if (query == null)
            query = new PasswdQuery();

        method.search(objectClass, query).forEach(resultsHandler::handle);
    }

    /**
     * Retrieving the configuration for the connector.
     *
     * @return Returns a PasswdConfiguration instance.
     */
    @Override
    public Configuration getConfiguration() {
        return configuration;
    }

    /**
     * Initializing the connector.
     *
     * @param configuration         The configuration for the connector.
     */
    @Override
    public void init(Configuration configuration) {
        configuration.validate();

        this.configuration = (PasswdConfiguration) configuration;
        this.connection    = ConnectionFactory.newInstance(this.configuration);
        this.method        = MethodFactory.newInstance(this.connection, this.configuration);
    }

    /**
     * Removing attribute values from an existing object.
     *
     * @param objectClass           The object class.
     * @param uid                   The UID of the object.
     * @param attributes            The attributes that should be removed.
     * @param operationOptions      The operation options.
     *
     * @return Returns the (possibly changed) UID of the object.
     */
    @Override
    public Uid removeAttributeValues(ObjectClass objectClass, Uid uid, Set<Attribute> attributes, OperationOptions operationOptions) {
        Set<AttributeDelta> attributeDeltas = new HashSet<>(attributes.size());

        for (Attribute attribute : attributes) {
            attributeDeltas.add(AttributeDeltaBuilder.build(
                    attribute.getName(),
                    Collections.emptySet(),
                    attribute.getValue()
            ));
        }

        return method.update(objectClass, uid, attributeDeltas);
    }

    /**
     * Runs a custom script on the resource.
     *
     * @param scriptContext         The script context.
     * @param operationOptions      The operation options.
     *
     * @return Returns the result of the custom script.
     */
    @Override
    public Object runScriptOnResource(ScriptContext scriptContext, OperationOptions operationOptions) {
        return null;
    }

    /**
     * Retrieving the schema for the connector.
     *
     * @return Returns a Schema instance.
     */
    @Override
    public Schema schema() {
        SchemaBuilder schemaBuilder = new SchemaBuilder(getClass());

        PasswdAccount.schema(configuration, schemaBuilder);
        PasswdGroup.schema(schemaBuilder);

        return schemaBuilder.build();
    }

    /**
     * Testing the connection.
     */
    @Override
    public void test() {
        method.test();
    }

    /**
     * Updating an object on the resource.
     *
     * @param objectClass           The object class.
     * @param uid                   The UID of the object.
     * @param attributes            The new attributes for the object.
     * @param operationOptions      The operation options.
     *
     * @return Returns the (possibly new) UID of the object.
     */
    @Override
    public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> attributes, OperationOptions operationOptions) {
        Set<AttributeDelta> attributeDeltas = new HashSet<>(attributes.size());

        for (Attribute attribute : attributes) {
            attributeDeltas.add(AttributeDeltaBuilder.build(
                    attribute.getName(),
                    attribute.getValue()
            ));
        }

        return method.update(objectClass, uid, attributeDeltas);
    }

    /**
     * Performs a delta-update operation for an object on the resource.
     *
     * @param objectClass           The object class.
     * @param uid                   The UID of the object.
     * @param attributeDeltas       The attribute deltas.
     * @param operationOptions      The operation options.
     *
     * @return Returns the attribute deltas that changed as a side effect.
     */
    @Override
    public Set<AttributeDelta> updateDelta(ObjectClass objectClass, Uid uid, Set<AttributeDelta> attributeDeltas, OperationOptions operationOptions) {
        method.update(objectClass, uid, attributeDeltas);

        return Collections.emptySet();
    }
}
