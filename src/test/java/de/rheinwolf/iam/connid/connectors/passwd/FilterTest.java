package de.rheinwolf.iam.connid.connectors.passwd;

import de.rheinwolf.iam.connid.connectors.passwd.init.ConnectorFactory;

import org.assertj.core.api.Assertions;

import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;

import org.mockito.Mockito;

import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.List;

/**
 * Testing the connector filters.
 */
public class FilterTest {
    @Test
    public void testEmptyFilter() {
        PasswdConnector  connector        = ConnectorFactory.newInstance();
        Filter           filter           = Mockito.mock(Filter.class);
        ObjectClass      objectClass      = new ObjectClass(ObjectClass.ACCOUNT_NAME);
        OperationOptions operationOptions = new OperationOptions(new HashMap<>(0));

        FilterTranslator<PasswdQuery> filterTranslator = connector.createFilterTranslator(objectClass, operationOptions);

        Assertions.assertThat(filterTranslator).isNotNull();
        Assertions.assertThat(filterTranslator).isInstanceOf(PasswdFilterTranslator.class);

        List<PasswdQuery> queries = filterTranslator.translate(filter);

        Assertions.assertThat(queries).hasSize(0);
    }
}
