package com.carmatechnologies.servlet;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.jvnet.libpam.PAM;
import org.jvnet.libpam.PAMException;
import org.jvnet.libpam.UnixUser;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Base64;

import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class PamAuthFilterTest {
    private static final String AUTHORIZATION = "Authorization";
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";
    private static final String BASIC_REALM_TATOOINE = "Basic realm=\"Tatooine\"";
    private static final int HTTP_STATUS_CODE_401_AUTHORIZED = 401;
    private static final Charset UTF_8 = Charset.forName("UTF-8"); // UTF-8: eight-bit UCS Transformation Format.

    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private final FilterChain filterChain = mock(FilterChain.class);
    private final FilterConfig filterConfig = mock(FilterConfig.class);
    private final PAM pam = mock(PAM.class);
    private final PamAuthFilter filter = new PamAuthFilter((String) -> pam);

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws ServletException {
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(filterConfig.getInitParameter("realm")).thenReturn("Tatooine");
        when(filterConfig.getInitParameter("service")).thenReturn("pam-servlet-filter");
        filter.init(filterConfig);
    }

    @After
    public void tearDown() {
        filter.destroy();
    }

    @Test
    public void authorisedUserShouldProceedToTheNextFilter() throws IOException, ServletException, PAMException {
        when(pam.authenticate("luke_skywalker", "pass123")).thenReturn(mock(UnixUser.class));
        when(request.getHeader(AUTHORIZATION)).thenReturn("Basic bHVrZV9za3l3YWxrZXI6cGFzczEyMw=="); // luke_skywalker:pass123
        filter.doFilter(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void authorisedUserShouldProceedToTheNextFilter_withEmptyPassword() throws IOException, ServletException, PAMException {
        when(pam.authenticate("user_with_empty_password", "")).thenReturn(mock(UnixUser.class));
        when(request.getHeader(AUTHORIZATION)).thenReturn("Basic dXNlcl93aXRoX2VtcHR5X3Bhc3N3b3JkOg=="); // user_with_empty_password:
        filter.doFilter(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void unauthorisedUserShouldReturnError401() throws IOException, ServletException, PAMException {
        when(pam.authenticate("darth_vader", "secret456")).thenThrow(new PAMException("Sith Lords are not allowed here, go away!"));
        when(request.getHeader(AUTHORIZATION)).thenReturn("Basic ZGFydGhfdmFkZXI6c2VjcmV0NDU2"); // darth_vader:secret456
        filter.doFilter(request, response, filterChain);
        verify(response).setHeader(WWW_AUTHENTICATE, BASIC_REALM_TATOOINE);
        verify(response).sendError(HTTP_STATUS_CODE_401_AUTHORIZED);
    }

    @Test
    public void unauthorisedUserShouldReturnError401_withEmptyPassword() throws IOException, ServletException, PAMException {
        when(pam.authenticate("user_with_empty_password", "")).thenThrow(new PAMException("Who the hell are you?! Go away!"));
        when(request.getHeader(AUTHORIZATION)).thenReturn("Basic dXNlcl93aXRoX2VtcHR5X3Bhc3N3b3JkOg=="); // user_with_empty_password:
        filter.doFilter(request, response, filterChain);
        verify(response).setHeader(WWW_AUTHENTICATE, BASIC_REALM_TATOOINE);
        verify(response).sendError(HTTP_STATUS_CODE_401_AUTHORIZED);
    }

    @Test
    public void nullAuthorizationHeaderShouldReturnError401() throws IOException, ServletException {
        when(request.getHeader(AUTHORIZATION)).thenReturn(null);
        filter.doFilter(request, response, filterChain);
        verify(response).sendError(HTTP_STATUS_CODE_401_AUTHORIZED);
    }

    @Test
    public void emptyAuthorizationHeaderShouldReturnError401() throws IOException, ServletException {
        when(request.getHeader(AUTHORIZATION)).thenReturn("");
        filter.doFilter(request, response, filterChain);
        verify(response).setHeader(WWW_AUTHENTICATE, BASIC_REALM_TATOOINE);
        verify(response).sendError(HTTP_STATUS_CODE_401_AUTHORIZED);
    }

    @Test
    public void blankAuthorizationHeaderShouldReturnError401() throws IOException, ServletException {
        when(request.getHeader(AUTHORIZATION)).thenReturn("     ");
        filter.doFilter(request, response, filterChain);
        verify(response).setHeader(WWW_AUTHENTICATE, BASIC_REALM_TATOOINE);
        verify(response).sendError(HTTP_STATUS_CODE_401_AUTHORIZED);
    }

    @Test
    public void malformedAuthorizationHeaderShouldReturnError401_HeaderHasTooManyFields() throws IOException, ServletException {
        when(request.getHeader(AUTHORIZATION)).thenReturn("Basic quantumly encrypted credentials bHVrZV9za3l3YWxrZXI6cGFzczEyMw==");
        filter.doFilter(request, response, filterChain);
        verify(response).setHeader(WWW_AUTHENTICATE, BASIC_REALM_TATOOINE);
        verify(response).sendError(HTTP_STATUS_CODE_401_AUTHORIZED);
    }

    @Test
    public void malformedAuthorizationHeaderShouldReturnError401_HeaderDoesNotStartWithBasic() throws IOException, ServletException {
        when(request.getHeader(AUTHORIZATION)).thenReturn("Complex bHVrZV9za3l3YWxrZXI6cGFzczEyMw==");
        filter.doFilter(request, response, filterChain);
        verify(response).setHeader(WWW_AUTHENTICATE, BASIC_REALM_TATOOINE);
        verify(response).sendError(HTTP_STATUS_CODE_401_AUTHORIZED);
    }

    @Test
    public void malformedAuthorizationHeaderShouldReturnError401_BasicCredentialsAreNotBase64Encoded() throws IOException, ServletException {
        when(request.getHeader(AUTHORIZATION)).thenReturn("Basic Hello-World!");
        filter.doFilter(request, response, filterChain);
        verify(response).setHeader(WWW_AUTHENTICATE, BASIC_REALM_TATOOINE);
        verify(response).sendError(HTTP_STATUS_CODE_401_AUTHORIZED);
    }

    @Test
    public void malformedAuthorizationHeaderShouldReturnError401_BasicCredentialsAreNotColonSeparated() throws IOException, ServletException {
        when(request.getHeader(AUTHORIZATION)).thenReturn("Basic bm9Db2xvbkJldHdlZW5Vc2VybmFtZUFuZFBhc3N3b3Jk"); // noColonBetweenUsernameAndPassword
        filter.doFilter(request, response, filterChain);
        verify(response).setHeader(WWW_AUTHENTICATE, BASIC_REALM_TATOOINE);
        verify(response).sendError(HTTP_STATUS_CODE_401_AUTHORIZED);
    }

    @Test
    public void malformedAuthorizationHeaderShouldReturnError401_BasicCredentialsWithEmptyUsername() throws IOException, ServletException {
        when(request.getHeader(AUTHORIZATION)).thenReturn("Basic OnNlY3JldF9wYXNzd29yZF9iZWxvbmdpbmdfdG9fbm9fb25l"); // :secret_password_belonging_to_no_one
        filter.doFilter(request, response, filterChain);
        verify(response).setHeader(WWW_AUTHENTICATE, BASIC_REALM_TATOOINE);
        verify(response).sendError(HTTP_STATUS_CODE_401_AUTHORIZED);
    }

    @Test
    public void creatingFilterWithNullPamFactoryThrowsNullPointerException() {
        exception.expect(NullPointerException.class);
        exception.expectMessage(equalTo("Please provide a non-null PAM factory."));
        new PamAuthFilter(null);
    }

    @Test
    public void initFilterShouldSetRealmToTheProvidedValue() throws ServletException {
        assertThat(filter.realm(), is("Tatooine"));
    }

    @Test
    public void initFilterShouldSetPamServiceToTheProvidedValue() throws ServletException {
        assertThat(filter.service(), is("pam-servlet-filter"));
    }

    @Test
    public void initFilterWithNullRealmThrowsServletException() throws ServletException {
        PamAuthFilter filter = new PamAuthFilter((String) -> pam);
        when(filterConfig.getInitParameter("realm")).thenReturn(null);
        when(filterConfig.getInitParameter("service")).thenReturn("pam-servlet-filter");
        exception.expect(ServletException.class);
        exception.expectMessage(equalTo("Please provide a non-null 'realm': [null]."));
        filter.init(filterConfig);
    }

    @Test
    public void initFilterWithEmptyRealmThrowsServletException() throws ServletException {
        PamAuthFilter filter = new PamAuthFilter((String) -> pam);
        when(filterConfig.getInitParameter("realm")).thenReturn("");
        when(filterConfig.getInitParameter("service")).thenReturn("pam-servlet-filter");
        exception.expect(ServletException.class);
        exception.expectMessage(equalTo("Please provide a non-blank 'realm': []."));
        filter.init(filterConfig);
    }

    @Test
    public void initFilterWithBlankRealmThrowsServletException() throws ServletException {
        PamAuthFilter filter = new PamAuthFilter((String) -> pam);
        when(filterConfig.getInitParameter("realm")).thenReturn("    ");
        when(filterConfig.getInitParameter("service")).thenReturn("pam-servlet-filter");
        exception.expect(ServletException.class);
        exception.expectMessage(equalTo("Please provide a non-blank 'realm': [    ]."));
        filter.init(filterConfig);
    }

    @Test
    public void initFilterWithNullServiceThrowsServletException() throws ServletException {
        PamAuthFilter filter = new PamAuthFilter((String) -> pam);
        when(filterConfig.getInitParameter("realm")).thenReturn("Tatooine");
        when(filterConfig.getInitParameter("service")).thenReturn(null);
        exception.expect(ServletException.class);
        exception.expectMessage(equalTo("Please provide a non-null 'service': [null]."));
        filter.init(filterConfig);
    }

    @Test
    public void initFilterWithEmptyServiceThrowsServletException() throws ServletException {
        PamAuthFilter filter = new PamAuthFilter((String) -> pam);
        when(filterConfig.getInitParameter("realm")).thenReturn("Tatooine");
        when(filterConfig.getInitParameter("service")).thenReturn("");
        exception.expect(ServletException.class);
        exception.expectMessage(equalTo("Please provide a non-blank 'service': []."));
        filter.init(filterConfig);
    }

    @Test
    public void initFilterWithBlankServiceThrowsServletException() throws ServletException {
        PamAuthFilter filter = new PamAuthFilter((String) -> pam);
        when(filterConfig.getInitParameter("realm")).thenReturn("Tatooine");
        when(filterConfig.getInitParameter("service")).thenReturn("    ");
        exception.expect(ServletException.class);
        exception.expectMessage(equalTo("Please provide a non-blank 'service': [    ]."));
        filter.init(filterConfig);
    }

    @Test
    public void authorisedUserShouldProceedToTheNextFilter_FunctionalTest() throws IOException, ServletException {
        final String username = System.getenv("PAM_USERNAME");
        final String password = System.getenv("PAM_PASSWORD");
        // Functional test: only run when the above environment variables are set. N.B.: you must use real credentials.
        assumeThat(username, is(not(nullValue())));
        assumeThat(password, is(not(nullValue())));

        final String credentials = Base64.getEncoder().encodeToString(format("%s:%s", username, password).getBytes(UTF_8));
        final PamAuthFilter filter = new PamAuthFilter();

        final FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getInitParameter("realm")).thenReturn("Tatooine");
        when(filterConfig.getInitParameter("service")).thenReturn("sshd");
        filter.init(filterConfig);

        when(request.getHeader(AUTHORIZATION)).thenReturn("Basic " + credentials);
        filter.doFilter(request, response, filterChain);
        verify(filterChain).doFilter(request, response);
    }
}
