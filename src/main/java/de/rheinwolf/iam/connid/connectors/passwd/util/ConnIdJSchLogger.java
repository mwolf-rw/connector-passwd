package de.rheinwolf.iam.connid.connectors.passwd.util;

import com.jcraft.jsch.Logger;

import org.identityconnectors.common.logging.Log;

import java.util.HashMap;
import java.util.Map;

/**
 * Bridging the ConnID and JSch logging systems.
 */
public class ConnIdJSchLogger implements Logger {
    private static final Map<Integer, Log.Level> LEVEL_MAP = new HashMap<>(5);

    static {
        LEVEL_MAP.put(DEBUG, Log.Level.OK);
        LEVEL_MAP.put(INFO,  Log.Level.INFO);
        LEVEL_MAP.put(WARN,  Log.Level.WARN);
        LEVEL_MAP.put(ERROR, Log.Level.ERROR);
        LEVEL_MAP.put(FATAL, Log.Level.ERROR);
    }

    private final Class<?> clazz;
    private final Log      log;

    /**
     * Construct the logger with a class.
     *
     * @param clazz     The class for which the logging should be done.
     */
    private ConnIdJSchLogger(Class<?> clazz) {
        this.clazz = clazz;
        this.log   = Log.getLog(clazz);
    }

    /**
     * Creating a new ConnIdJSchLogger instance.
     *
     * @param clazz     The class for which the logging should be done.
     *
     * @return Returns a JSch Logger instance.
     */
    public static Logger newInstance(Class<?> clazz) {
        return new ConnIdJSchLogger(clazz);
    }

    /**
     * Checking whether the given log level is enabled.
     *
     * @param logLevel  The log level.
     *
     * @return Returns whether the log level is enabled.
     */
    @Override
    public boolean isEnabled(int logLevel) {
        return log.isLoggable(LEVEL_MAP.get(logLevel));
    }

    /**
     * Logs a message.
     *
     * @param logLevel  The log level.
     * @param message   The message.
     */
    @Override
    public void log(int logLevel, String message) {
        log.log(clazz, "JSch", LEVEL_MAP.get(logLevel), message, null);
    }
}
