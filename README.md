[![Build Status](https://travis-ci.org/marccarre/pam-servlet-filter.svg?branch=master)](https://travis-ci.org/marccarre/pam-servlet-filter) [![Coverage Status](https://coveralls.io/repos/github/marccarre/pam-servlet-filter/badge.svg)](https://coveralls.io/github/marccarre/pam-servlet-filter)

# PAM Authentication Servlet Filter

Servlet filter to authenticate users using Basic Authentication and PAM (Linux Pluggable Authentication Modules).

It enables users to login using their Linux, SSH, SSO, etc. credentials, or even to leverage LDAP, Kerberos, biometrics, or any other 3rd party authentication & authorisation solution which integrates with PAM.

## Dependencies:

1. Servlet container must be deployed on an operating system leveraging PAM (e.g.: Linux, macOS, etc.).
2. The PAM `service` configured (details below) must be configured to authenticate users.
3. The filter only depends on [`org.kohsuke:libpam4j`](https://github.com/kohsuke/libpam4j), which itself only depends on [`net.java.dev.jna:jna`](https://github.com/java-native-access/jna).
   No other 3rd party libraries are used or packaged in the "fat" JAR.

## Usage:

- add the appropriate JAR to your classpath, i.e. either:

  - the "thin" JAR, i.e. [`pam-servlet-filter-{version}.jar`](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.carmatechnologies.servlet%22%20a%3A%22pam-servlet-filter%22), if you already have [`org.kohsuke:libpam4j`](https://github.com/kohsuke/libpam4j) and [`net.java.dev.jna:jna`](https://github.com/java-native-access/jna) on your classpath, or
  - the "fat" JAR, i.e. [`pam-servlet-filter-{version}-all.jar`](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.carmatechnologies.servlet%22%20a%3A%22pam-servlet-filter%22), if you do not have these already.

- optionally, create `/etc/pam.d/{application}` and configure it to be able to authenticate using PAM, e.g.:

        # PAM configuration for {application}
        # Standard Un*x authentication.
        @include common-auth

  For additional information on PAM, please consider consulting these resources:

    - http://tldp.org/HOWTO/User-Authentication-HOWTO/x115.html
    - http://www.linux-pam.org/Linux-PAM-html/sag-overview.html
    - http://www.linux-pam.org/Linux-PAM-html/sag-configuration.html

- optionally, and depending your web application, add the filter to your `web.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://java.sun.com/xml/ns/javaee"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://java.sun.com/xml/ns/javaee
    http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd"
    version="3.0">

  <filter>
    <filter-name>pamAuthFilter</filter-name>
    <filter-class>com.carmatechnologies.servlet.PamAuthFilter</filter-class>
    <!-- This is the Basic Authentication "realm" which you are protecting, e.g. the name of the application. 
         This value is presented to end users who are trying to log in. -->
    <init-param>
      <param-name>realm</param-name>
      <param-value>{applicationName}</param-value>
    </init-param>
     <!-- This is the PAM service you will use behind the scene, configured at /etc/pam.d/{application}. -->
    <init-param>
      <param-name>service</param-name>
      <param-value>{application}</param-value>
    </init-param>
  </filter>
  
  <filter-mapping>
    <filter-name>pamAuthFilter</filter-name>
    <url-pattern>/login.jsp</url-pattern>
  </filter-mapping>
</web-app>
```

#### Important:

- Basic authentication does *NOT* encrypt credentials, so be sure to use SSL/TLS.
- Depending on how the provided PAM `service` is configured, if your application does not run as `root`, and if you need PAM to access encrypted passwords in `/etc/shadow`, you may need to set the `shadow` group to the user running the application.

## License:

[Apache License Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) -- see also [LICENSE](https://raw.githubusercontent.com/marccarre/pam-servlet-filter/master/LICENSE)

## Build:

- Compile, test and generate code coverage report:

        ./gradlew clean test

- Compile, package JARs, sign JARs, test, generate code coverage reports, and (when under CI server) publish them:

        ./gradlew clean build


## Release:

1. Change version in `build.gradle` and commit.
2. Run: `git tag -a X.Y.Z -m "X.Y.Z"`
3. Run: `git push origin --tags`
4. Create `~/.gradle/gradle.properties` and ensure it contains the required properties:

        signing.keyId=<keyID>  # 8 unique characters visible when you run $ gpg --list-keys
        signing.password=<password>
        signing.secretKeyRingFile=/home/<username>/.gnupg/secring.gpg

        ossrhUsername=<username>
        ossrhPassword=<password>

5. Run: `./gradlew uploadArchives`
6. Run: `./gradlew closeAndPromoteRepository`

See also: 

- [Sonatype's Gradle documentation](http://central.sonatype.org/pages/gradle.html)
- [Gradle Nexus Staging plugin's documentation](https://github.com/Codearte/gradle-nexus-staging-plugin/)

