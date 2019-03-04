package de.rheinwolf.iam.connid.connectors.passwd.method.passwd;

import de.rheinwolf.iam.connid.connectors.passwd.PasswdQuery;
import de.rheinwolf.iam.connid.connectors.passwd.connection.CommandResult;
import de.rheinwolf.iam.connid.connectors.passwd.file.PasswdFile;
import de.rheinwolf.iam.connid.connectors.passwd.model.MasterPasswdField;
import de.rheinwolf.iam.connid.connectors.passwd.util.CommandBuilder;
import de.rheinwolf.iam.connid.connectors.passwd.util.GuardedStringAccessor;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectionBrokenException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;

import java.util.*;
import java.util.stream.Collectors;

import static de.rheinwolf.iam.connid.connectors.passwd.model.MasterPasswdField.*;
import static de.rheinwolf.iam.connid.connectors.passwd.model.GroupField.MEMBERS;

/**
 * Updating the passwd database using pw.
 */
public class PwPasswdMethod extends AbstractPasswdMethod {
    private static final String COMMAND_PW      = "pw";
    private static final String COMMAND_WHEREIS = "whereis";

    private static final Map<String, String> SWITCHES_MAP_ACCOUNT = new HashMap<>();
    private static final Map<String, String> SWITCHES_MAP_GROUP   = new HashMap<>();

    static {
        SWITCHES_MAP_ACCOUNT.put(Name.NAME,                                                   "-n");
        SWITCHES_MAP_ACCOUNT.put(ACCOUNT_EXPIRATION_TIME.getAttributes().getAttributeName(),  "-e");
        SWITCHES_MAP_ACCOUNT.put(COMMENT.getAttributes().getAttributeName(),                  "-c");
        SWITCHES_MAP_ACCOUNT.put(GID.getAttributes().getAttributeName(),                      "-g");
        SWITCHES_MAP_ACCOUNT.put(HOME_DIRECTORY.getAttributes().getAttributeName(),           "-d");
        SWITCHES_MAP_ACCOUNT.put(LOGIN_CLASS.getAttributes().getAttributeName(),              "-L");
        SWITCHES_MAP_ACCOUNT.put(LOGIN_SHELL.getAttributes().getAttributeName(),              "-s");
        SWITCHES_MAP_ACCOUNT.put(PASSWORD_EXPIRATION_TIME.getAttributes().getAttributeName(), "-p");
        SWITCHES_MAP_ACCOUNT.put(UID.getAttributes().getAttributeName(),                      "-u");

        SWITCHES_MAP_GROUP.put(Name.NAME,                                  "-n");
        SWITCHES_MAP_GROUP.put(GID.getAttributes().getAttributeName(),     "-g");
        SWITCHES_MAP_GROUP.put(MEMBERS.getAttributes().getAttributeName(), "-M");
    }

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
        String loginName = getName(attributes);

        if (loginName == null)
            throw new InvalidAttributeValueException("Missing attribute loginName");

        List<String>  args     = getPwArgs(objectClass, "add", null, attributes, Collections.emptySet());
        byte[]        password = getPassword(attributes);

        if (objectClass.is(ObjectClass.ACCOUNT_NAME)) {
            if (configuration.getCreateHomeDirectory())
                args.add("-m");

            if (!StringUtil.isBlank(configuration.getHomeDirectoryPermissions())) {
                args.add("-M");
                args.add(configuration.getHomeDirectoryPermissions());
            }
        }

        if ((password != null) && (password.length > 0)) {
            args.add("-h");
            args.add("0");
        }

        CommandResult commandResult = becomeMethod.execute(connection, password, COMMAND_PW, args.toArray(new String[0]))
                .expect(0, 65);

        if (commandResult.getExitCode() == 65)
            throw new AlreadyExistsException();

        commandResult.expectStdErrIsEmpty();

        return new Uid(loginName);
    }

    /**
     * Deleting an object.
     *
     * @param objectClass       The object class.
     * @param uid               The UID of the object.
     */
    @Override
    public void delete(ObjectClass objectClass, Uid uid) {
        List<String> args = getPwArgs(objectClass, "del", uid, Collections.emptySet(), Collections.emptySet());

        if ((objectClass.is(ObjectClass.ACCOUNT_NAME)) && (configuration.getDeleteHomeDirectory()))
            args.add("-r");

        becomeMethod.execute(connection, null, COMMAND_PW, args.toArray(new String[0]))
                .expect(0)
                .expectStdErrIsEmpty();
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
        Set<Attribute> attributesToRemove  = new HashSet<>(0);
        Set<Attribute> attributesToReplace = new HashSet<>(attributes.size());
        AttributeDelta newMembers          = null;
        String         newName             = null;
        byte[]         password            = null;

        for (AttributeDelta attributeDelta : attributes) {
            if (attributeDelta.is(Name.NAME)) {
                newName = getValue(attributeDelta);
            } else if (attributeDelta.is(MEMBERS.getAttributes().getAttributeName())) {
                newMembers = attributeDelta;
            } else if (attributeDelta.is(PASSWORD.getAttributes().getAttributeName())) {
                password = GuardedStringAccessor.asByteArray(getValue(attributeDelta));
            } else {
                if ((attributeDelta.getValuesToRemove() != null) && (!attributeDelta.getValuesToRemove().isEmpty())) {
                    attributesToRemove.add(AttributeBuilder.build(
                            attributeDelta.getName(),
                            ""
                    ));
                } else {
                    attributesToReplace.add(AttributeBuilder.build(
                            attributeDelta.getName(),
                            (Object) getValue(attributeDelta)
                    ));
                }
            }
        }

        List<String> args = getPwArgs(objectClass, "mod", uid, attributesToReplace, attributesToRemove);

        if (newName != null) {
            args.add("-l");
            args.add(CommandBuilder.toCommandValue(newName));
        }

        if ((newMembers != null) && (newMembers.getValuesToReplace() != null) && (!newMembers.getValuesToReplace().isEmpty())) {
            args.add("-M");
            args.add(newMembers.getValuesToReplace().stream()
                    .map(CommandBuilder::toCommandValue)
                    .collect(Collectors.joining(",")));
        } else if (newMembers != null) {
            if ((newMembers.getValuesToAdd() != null) && (!newMembers.getValuesToAdd().isEmpty())) {
                args.add("-m");
                args.add(newMembers.getValuesToAdd().stream()
                        .map(CommandBuilder::toCommandValue)
                        .collect(Collectors.joining(",")));
            }

            if ((newMembers.getValuesToRemove() != null) && (!newMembers.getValuesToRemove().isEmpty())) {
                args.add("-d");
                args.add(newMembers.getValuesToRemove().stream()
                        .map(CommandBuilder::toCommandValue)
                        .collect(Collectors.joining(",")));
            }
        }

        if ((password != null) && (password.length > 0)) {
            args.add("-h");
            args.add("0");
        }

        becomeMethod.execute(connection, password, COMMAND_PW, args.toArray(new String[0]))
                .expect(0)
                .expectStdErrIsEmpty();

        if (newName != null)
            return new Uid(newName);

        return uid;
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
        List<String> args = getPwArgs(objectClass, "show", null, Collections.emptySet(), Collections.emptySet());

        args.add("-a");

        return becomeMethod.execute(connection, null, COMMAND_PW, args.toArray(new String[0]))
                .expect(0)
                .expectStdErrIsEmpty()
                .getStdOut()
                .stream()
                .map(line -> PasswdFile.toConnectorObject(objectClass, line, MasterPasswdField.values()))
                .filter(Objects::nonNull)
                .filter(query::matches)
                .collect(Collectors.toList());
    }

    /**
     * Testing the connection and method.
     */
    @Override
    public void test() {
        becomeMethod.execute(connection, null, COMMAND_WHEREIS, COMMAND_PW)
                .expect(0)
                .expectStdErrIsEmpty();
    }

    /**
     * Retrieving the arguments for a call to pw.
     *
     * @param objectClass           The object class.
     * @param mode                  The mode (add, del, mod).
     * @param uid                   The UID of the object. Can be null.
     * @param attributesToReplace   The attributes for the call that should be replaced.
     * @param attributesToRemove    The attributes for the call that should be removed.
     *
     * @return Returns a modifiable list of arguments for the pw call.
     */
    private List<String> getPwArgs(ObjectClass objectClass, String mode, Uid uid, Set<Attribute> attributesToReplace, Set<Attribute> attributesToRemove) {
        List<String>        args = new ArrayList<>();
        Map<String, String> switchesMap;

        if (objectClass.is(ObjectClass.ACCOUNT_NAME)) {
            switchesMap = SWITCHES_MAP_ACCOUNT;
            args.add("user");
        } else if (objectClass.is(ObjectClass.GROUP_NAME)) {
            switchesMap = SWITCHES_MAP_GROUP;
            args.add("group");
        } else {
            throw new ConnectionBrokenException("Invalid object class: " + objectClass.getObjectClassValue());
        }

        args.add(mode);

        if (uid != null) {
            args.add(switchesMap.get(Name.NAME));
            args.add(uid.getUidValue());
        }

        for (Attribute attribute : attributesToReplace) {
            if (OperationalAttributeInfos.PASSWORD.is(attribute.getName()))
                continue;

            args.add(getSwitchForAttribute(objectClass, attribute.getName()));
            args.add(attribute.getValue().stream()
                    .map(CommandBuilder::toCommandValue)
                    .collect(Collectors.joining(",")));
        }

        for (Attribute attribute : attributesToRemove) {
            args.add(getSwitchForAttribute(objectClass, attribute.getName()));
            args.add("");
        }

        return args;
    }

    /**
     * Retrieving the password from the attribute set.
     *
     * @param attributes        The attribute set.
     *
     * @return Returns an byte array containing the password if found, null otherwise.
     */
    private byte[] getPassword(Set<Attribute> attributes) {
        List<Object> value = null;

        for (Attribute attribute : attributes) {
            if (!OperationalAttributeInfos.PASSWORD.is(attribute.getName()))
                continue;

            value = attribute.getValue();
            break;
        }

        if ((value == null) || (value.isEmpty()))
            return null;

        if (!(value.get(0) instanceof GuardedString))
            throw new InvalidAttributeValueException("Password attribute is not a GuardedString instance");

        return GuardedStringAccessor.asByteArray((GuardedString) value.get(0));
    }

    /**
     * Retrieving the naming attribute from a set.
     *
     * @param attributes        The attribute set.
     *
     * @return Returns the naming attribute if it is in the set, null otherwise.
     */
    private String getName(Set<Attribute> attributes) {
        for (Attribute attribute : attributes) {
            if (attribute.is(Name.NAME))
                return (String) attribute.getValue().get(0);
        }

        return null;
    }

    /**
     * Retrieving the switch for a given attribute.
     *
     * @param objectClass       The object class.
     * @param attributeName     The attribute name.
     *
     * @return Returns the pw switch for the attribute.
     */
    private String getSwitchForAttribute(ObjectClass objectClass, String attributeName) {
        Map<String, String> switchesMap;

        if (objectClass.is(ObjectClass.ACCOUNT_NAME)) {
            switchesMap = SWITCHES_MAP_ACCOUNT;
        } else if (objectClass.is(ObjectClass.GROUP_NAME)) {
            switchesMap = SWITCHES_MAP_GROUP;
        } else {
            throw new ConnectionBrokenException("Invalid object class: " + objectClass.getObjectClassValue());
        }

        String switchName = switchesMap.get(attributeName);

        if (switchName == null) {
            throw new InvalidAttributeValueException("Invalid attribute " + attributeName);
        }

        return switchName;
    }

    /**
     * Retrieving a string value from an AttributeDelta.
     *
     * @param attributeDelta    The attribute delta.
     *
     * @return Returns a single string from the delta, or null if no value should be added or replaced.
     */
    @SuppressWarnings("unchecked")
    private <T> T getValue(AttributeDelta attributeDelta) {
        if ((attributeDelta.getValuesToAdd() != null) && (!attributeDelta.getValuesToAdd().isEmpty()))
            return (T) attributeDelta.getValuesToAdd().get(0);

        if ((attributeDelta.getValuesToReplace() != null) && (!attributeDelta.getValuesToReplace().isEmpty()))
            return (T) attributeDelta.getValuesToReplace().get(0);

        return null;
    }
}
