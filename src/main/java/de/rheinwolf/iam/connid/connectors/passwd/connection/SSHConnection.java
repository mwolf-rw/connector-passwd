package de.rheinwolf.iam.connid.connectors.passwd.connection;

import com.jcraft.jsch.*;

import de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration;
import de.rheinwolf.iam.connid.connectors.passwd.util.CommandBuilder;
import de.rheinwolf.iam.connid.connectors.passwd.util.ConnIdJSchLogger;
import de.rheinwolf.iam.connid.connectors.passwd.util.GuardedStringAccessor;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectionBrokenException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

/**
 * Connecting to target systems using SSH.
 */
public class SSHConnection implements Connection {
    private static final Log LOG = Log.getLog(SSHConnection.class);

    private final JSch jSch = new JSch();

    private Session session = null;

    /**
     * Trying to authenticate using a username/password pair.
     *
     * @param configuration     The configuration instance.
     * @param username          The username.
     * @param password          The password.
     */
    @Override
    public void authenticate(PasswdConfiguration configuration, String username, GuardedString password) {
        try {
            Session authSession = jSch.getSession(configuration.getUserName(), configuration.getHostName(), configuration.getPort());

            if (StringUtil.isBlank(configuration.getHostKey())) {
                LOG.info("Using known hosts from default location - consider setting host key explicitly");
            } else if ("*".equals(configuration.getHostKey())) {
                authSession.setConfig("StrictHostKeyChecking", "no");
            }

            authSession.setConfig("PreferredAuthentications", "password");
            authSession.setPassword(GuardedStringAccessor.asByteArray(password));

            authSession.connect();
            authSession.disconnect();
        } catch (JSchException e) {
            throw new ConnectionFailedException("Could not connect to " + configuration.getHostName(), e);
        }
    }

    /**
     * Closing the connection.
     */
    @Override
    public void close() {
        if ((session != null) && (session.isConnected())) {
            LOG.ok("close() -> Disconnecting from {0}", session.getHost());
            session.disconnect();
        }

        session = null;
    }

    /**
     * Executing a command.
     *
     * @param stdin             The input for the command. Can be null.
     * @param args              The arguments for the command.
     *
     * @return Returns a CommandResult instance.
     */
    @Override
    public CommandResult execute(byte[] stdin, String... args) {
        CommandResult result = new CommandResult();
        ChannelExec   channel;

        try {
            channel = (ChannelExec) session.openChannel("exec");
        } catch (JSchException e) {
            throw new ConnectionBrokenException("Failed to open execute channel", e);
        }

        try {
            InputStream  commandOutput = channel.getInputStream();
            InputStream  commandErrOut = channel.getErrStream();
            OutputStream commandInput  = channel.getOutputStream();

            LOG.ok("Starting process: {0}", Arrays.toString(args));

            channel.setCommand(CommandBuilder.asString(args));
            channel.connect();

            if ((stdin != null) && (stdin.length > 0)) {
                commandInput.write(stdin);
                commandInput.close();
            }

            CommandResult.readCommandOutput(commandOutput, result::appendStdOut);
            CommandResult.readCommandOutput(commandErrOut, result::appendStdErr);

            if (channel.isClosed()) {
                result.setExitCode(channel.getExitStatus());
                LOG.ok("Process exited with exit code {0}", result.getExitCode());
            }
        } catch (IOException e) {
            throw new ConnectionBrokenException("Failed open output stream of execute channel", e);
        } catch (JSchException e) {
            throw new ConnectionBrokenException("Failed to connect to execute channel", e);
        } finally {
            channel.disconnect();
        }

        return result;
    }

    /**
     * Initializing the connection.
     *
     * @param configuration     The configuration instance.
     */
    @Override
    public void init(PasswdConfiguration configuration) {
        JSch.setLogger(ConnIdJSchLogger.newInstance(SSHConnection.class));

        try {
            LOG.ok("Connecting to {0}@{1}:{2}",
                    configuration.getUserName(),
                    configuration.getHostName(),
                    configuration.getPort());

            session = jSch.getSession(configuration.getUserName(), configuration.getHostName(), configuration.getPort());

            if (StringUtil.isBlank(configuration.getHostKey())) {
                LOG.info("Using known hosts from default location - consider setting host key explicitly");
            } else if ("*".equals(configuration.getHostKey())) {
                session.setConfig("StrictHostKeyChecking", "no");
            } else {
                jSch.setKnownHosts(new ByteArrayInputStream(
                        (configuration.getHostName() + " " + configuration.getHostKey()).getBytes()
                ));
            }

            if (!StringUtil.isBlank(configuration.getPrivateKey())) {
                session.setConfig("PreferredAuthentications", "publickey");
                jSch.addIdentity(
                        configuration.getPrivateKey(),
                        GuardedStringAccessor.asByteArray(configuration.getPassword())
                );
            } else {
                session.setConfig("PreferredAuthentications", "password");
                session.setPassword(GuardedStringAccessor.asByteArray(configuration.getPassword()));
            }

            session.connect();
        } catch (JSchException e) {
            throw new ConnectionFailedException("Could not connect to " + configuration.getHostName(), e);
        }
    }

    /**
     * Checking whether the connection is alive.
     *
     * @return Returns whether the connection is alive.
     */
    @Override
    public boolean isAlive() {
        if ((session == null) || (!session.isConnected()))
            return false;

        try {
            session.sendKeepAliveMsg();
        } catch (Exception e) {
            LOG.error(e, "isAlive() -> Could not send keep alive message to {0}", session.getHost());
            return false;
        }

        return true;
    }
}
