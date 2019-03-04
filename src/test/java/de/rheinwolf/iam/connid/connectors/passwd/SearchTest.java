package de.rheinwolf.iam.connid.connectors.passwd;

import de.rheinwolf.iam.connid.connectors.passwd.init.ConnectorFactory;

import org.assertj.core.api.Assertions;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;

import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import org.testng.annotations.Test;

import java.util.HashMap;

/**
 * Testing the search operations.
 */
public class SearchTest {
    private static final Log LOG = Log.getLog(SearchTest.class);

    @Test
    public void testAccountSearch() {
        testObjectClassSearch(ObjectClass.ACCOUNT_NAME);
    }

    @Test
    public void testGroupSearch() {
        testObjectClassSearch(ObjectClass.GROUP_NAME);
    }

    private void testObjectClassSearch(String className) {
        PasswdConnector  connector        = ConnectorFactory.newInstance();
        ResultsHandler   resultsHandler   = Mockito.mock(ResultsHandler.class);
        ObjectClass      objectClass      = new ObjectClass(className);
        OperationOptions operationOptions = new OperationOptions(new HashMap<>(0));

        connector.executeQuery(objectClass, null, resultsHandler, operationOptions);

        Mockito.verify(resultsHandler, Mockito.atLeast(26)).handle(ArgumentMatchers.argThat(connectorObject -> {
            LOG.info("ConnectorObject: {0}", connectorObject);

            Assertions.assertThat(connectorObject).isNotNull();
            Assertions.assertThat(connectorObject.getName()).isNotNull();
            Assertions.assertThat(connectorObject.getUid()).isNotNull();

            return true;
        }));
    }
}
