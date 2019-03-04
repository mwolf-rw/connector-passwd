package de.rheinwolf.iam.connid.connectors.passwd.connection;

import de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration;

import org.identityconnectors.common.security.GuardedString;

/**
 * Interface for implementing connections to target systems.
 */
public interface Connection extends AutoCloseable {
    /**
     * Trying to authenticate using a username/password pair.
     *
     * @param configuration     The configuration instance.
     * @param username          The username.
     * @param password          The password.
     */
    void authenticate(PasswdConfiguration configuration, String username, GuardedString password);

    /**
     * Closing the connection.
     */
    @Override
    void close();

    /**
     * Executing a command.
     *
     * @param stdin             The input for the command. Can be null.
     * @param args              The arguments for the command.
     *
     * @return Returns a CommandResult instance.
     */
    CommandResult execute(byte[] stdin, String... args);

    /**
     * Initializing the connection.
     *
     * @param configuration     The configuration instance.
     */
    void init(PasswdConfiguration configuration);

    /**
     * Checking whether the connection is alive.
     *
     * @return Returns whether the connection is alive.
     */
    boolean isAlive();
}
