package de.rheinwolf.iam.connid.connectors.passwd;

import de.rheinwolf.iam.connid.connectors.passwd.init.ConnectorFactory;

import org.assertj.core.api.Assertions;
import org.assertj.core.api.Condition;

import org.identityconnectors.framework.common.objects.*;

import org.testng.annotations.Test;

import java.util.Set;

/**
 * Testing the connector schema.
 */
public class SchemaTest {
    private static final Condition<ObjectClassInfo> isAccountObjectClass = new Condition<>(
            objectClassInfo -> objectClassInfo.is(ObjectClass.ACCOUNT_NAME),
            ObjectClass.ACCOUNT_NAME
    );

    private static final Condition<ObjectClassInfo> isGroupObjectClass = new Condition<>(
            objectClassInfo -> objectClassInfo.is(ObjectClass.GROUP_NAME),
            ObjectClass.GROUP_NAME
    );

    private static final Condition<AttributeInfo> isNameAttribute = new Condition<>(
            attributeInfo -> attributeInfo.is(Name.NAME),
            Name.NAME
    );

    private static final Condition<AttributeInfo> isUidAttribute = new Condition<>(
            attributeInfo -> attributeInfo.is(Uid.NAME),
            Uid.NAME
    );

    @Test
    public void testSchemaGeneration() {
        PasswdConnector connector = ConnectorFactory.newInstance();
        Schema          schema    = connector.schema();

        Assertions.assertThat(schema).isNotNull();

        Set<ObjectClassInfo> objectClassInfoSet = schema.getObjectClassInfo();

        Assertions.assertThat(objectClassInfoSet).haveExactly(1, isAccountObjectClass);
        Assertions.assertThat(objectClassInfoSet).haveExactly(1, isGroupObjectClass);

        for (ObjectClassInfo objectClassInfo : objectClassInfoSet) {
            Set<AttributeInfo> attributeInfos = objectClassInfo.getAttributeInfo();

            Assertions.assertThat(attributeInfos).haveExactly(1, isNameAttribute);
            Assertions.assertThat(attributeInfos).haveExactly(1, isUidAttribute);
        }
    }
}
