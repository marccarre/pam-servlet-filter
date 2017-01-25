package com.carmatechnologies.servlet;

import org.jvnet.libpam.PAM;
import org.jvnet.libpam.PAMException;
import org.jvnet.libpam.UnixUser;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.function.Function;
import java.util.logging.Logger;

import static java.lang.Character.isWhitespace;
import static java.lang.String.format;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

/**
 * Servlet filter to authenticate users using Basic Authentication and PAM (Linux Pluggable Authentication Modules).
 * It enables users to login using their Linux username and password.
 *
 * @author Marc CARRE (@marccarre / carre.marc@gmail.com)
 */
public class PamAuthFilter implements Filter {
    /**
     * Basic Authentication Scheme's realm.
     * See also: https://tools.ietf.org/html/rfc2617#section-2
     */
    public static final String REALM = "realm";

    /**
     * PAM service used to authenticate.
     * See:
     * - http://tldp.org/HOWTO/User-Authentication-HOWTO/x115.html
     * - http://www.linux-pam.org/Linux-PAM-html/sag-overview.html
     * - http://www.linux-pam.org/Linux-PAM-html/sag-configuration.html
     */
    public static final String SERVICE = "service";

    private static final String WHITESPACE = " ";
    private static final String COLON = ":";
    private static final int AT_MOST_ONCE = 2;
    private static final int TWO = 2;
    private static final String AUTHORIZATION = "Authorization";
    private static final int INDEX_USERNAME = 0;
    private static final int INDEX_PASSWORD = 1;
    private static final String BASIC = "Basic";
    private static final int INDEX_BASIC = 0;
    private static final int INDEX_CREDENTIALS = 1;
    private static final Charset UTF_8 = Charset.forName("UTF-8"); // UTF-8: eight-bit UCS Transformation Format.
    private static final String EMPTY = "";
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";
    private static final char STAR = '*';
    private static final char LEFT_SQUARE_BRACKET = '[';
    private static final char RIGHT_SQUARE_BRACKET = ']';
    private static final char COMMA = ',';

    private static final Logger logger = Logger.getLogger(PamAuthFilter.class.getSimpleName());

    private final Function<String, PAM> pamFactory;
    private String realm;
    private String service;
    private PAM pam;

    public PamAuthFilter() {
        this(PamAuthFilter::newPam);
    }

    private static PAM newPam(final String service) {
        try {
            return new PAM(service);
        } catch (final PAMException e) {
            throw new RuntimeException(e);
        }
    }

    PamAuthFilter(final Function<String, PAM> pamFactory) {
        if (pamFactory == null) {
            throw new NullPointerException("Please provide a non-null PAM factory.");
        }
        this.pamFactory = pamFactory;
    }

    public String realm() {
        return realm;
    }

    public String service() {
        return service;
    }

    @Override
    public void init(final FilterConfig config) throws ServletException {
        realm = checkNotBlank(config.getInitParameter(REALM), REALM);
        service = checkNotBlank(config.getInitParameter(SERVICE), SERVICE);
        logger.info(format("PAM authentication filter configured with %s=[%s] and %s=[%s].", REALM, realm, SERVICE, service));
        pam = pamFactory.apply(service);
    }

    private String checkNotBlank(final String value, final String name) throws ServletException {
        if (value == null) {
            throw new ServletException(format("Please provide a non-null '%s': [%s].", name, value));
        }
        if (isBlank(value)) {
            throw new ServletException(format("Please provide a non-blank '%s': [%s].", name, value));
        }
        return value;
    }

    private static boolean isBlank(final CharSequence characters) {
        int length;
        if (characters == null || (length = characters.length()) == 0) {
            return true;
        }
        for (int i = 0; i < length; i++) {
            if (!isWhitespace(characters.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final HttpServletResponse httpResponse = (HttpServletResponse) response;
        if (isAuthenticated(httpRequest)) {
            // Successfully authenticated, move to the next filter in the chain:
            chain.doFilter(httpRequest, httpResponse);
        } else {
            // Failed to authenticate user, respond with HTTP 401 Unauthorized:
            httpResponse.setHeader(WWW_AUTHENTICATE, format("%s realm=\"%s\"", BASIC, realm));
            httpResponse.sendError(SC_UNAUTHORIZED);
        }
    }

    private boolean isAuthenticated(final HttpServletRequest httpRequest) {
        final String auth = httpRequest.getHeader(AUTHORIZATION);
        if (isBlank(auth)) {
            logger.severe(format("Blank %s header [%s] from IP [%s].", AUTHORIZATION, auth, httpRequest.getRemoteAddr()));
            return false;
        }
        final String[] basic = auth.split(WHITESPACE, AT_MOST_ONCE);
        if ((basic.length != TWO) || !BASIC.equals(basic[INDEX_BASIC])) {
            logger.severe(format("Malformed %s header [%s] from IP [%s].", AUTHORIZATION, safelyRender(basic), httpRequest.getRemoteAddr()));
            return false;
        }
        final String[] credentials = base64Decode(basic[INDEX_CREDENTIALS], httpRequest).split(COLON, AT_MOST_ONCE);
        if ((credentials.length != TWO) || isBlank(credentials[INDEX_USERNAME])) {
            logger.severe(format("Malformed %s credentials. Encoded: [%s]. Decoded: [%s]. IP: [%s].", BASIC, basic[INDEX_CREDENTIALS], safelyRender(credentials), httpRequest.getRemoteAddr()));
            return false;
        }
        return isAuthenticated(credentials, httpRequest);
    }

    private String base64Decode(final String credentials, final HttpServletRequest httpRequest) {
        try {
            return new String(Base64.getDecoder().decode(credentials), UTF_8);
        } catch (final IllegalArgumentException e) {
            logger.severe(format("Malformed base64-encoded %s credentials [%s] from IP [%s]: %s", BASIC, credentials, httpRequest.getRemoteAddr(), e.getMessage()));
            return EMPTY;
        }
    }

    private String safelyRender(final String[] array) {
        final StringBuilder builder = new StringBuilder();
        final int last = array.length - 1;
        builder.append(LEFT_SQUARE_BRACKET);
        for (int i = 0; i < array.length; ++i) {
            appendOrMask(builder, array, i);
            if (i < last) {
                builder.append(COMMA);
            }
        }
        builder.append(RIGHT_SQUARE_BRACKET);
        return builder.toString();
    }

    private void appendOrMask(final StringBuilder builder, final String[] array, final int i) {
        builder.append(LEFT_SQUARE_BRACKET);
        if ((i == INDEX_USERNAME) || (i == INDEX_BASIC)) {
            // 'Basic' header and username fields should typically be safe to print:
            builder.append(array[i]);
        } else {
            // Mask details to avoid accidentally leaking information in the logs (e.g. parts of a password):
            for (int j = 0; j < array[i].length(); ++j) {
                builder.append(STAR);
            }
        }
        builder.append(RIGHT_SQUARE_BRACKET);
    }

    private boolean isAuthenticated(final String[] credentials, final HttpServletRequest httpRequest) {
        try {
            final UnixUser user = pam.authenticate(credentials[INDEX_USERNAME], credentials[INDEX_PASSWORD]);
            logger.info(format("Successfully authenticated [%s] with IP [%s], UID [%s], GID [%s] and groups [%s].", user.getUserName(), httpRequest.getRemoteAddr(), user.getUID(), user.getGID(), user.getGroups()));
            return true;
        } catch (final PAMException e) {
            logger.severe(format("Failed to authenticate [%s] with IP [%s]: %s", credentials[INDEX_USERNAME], httpRequest.getRemoteAddr(), e.getMessage()));
            return false;
        }
    }

    @Override
    public void destroy() {
        pam.dispose();
    }
}
