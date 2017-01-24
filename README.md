[![Build Status](https://travis-ci.org/marccarre/pam-servlet-filter.svg?branch=master)](https://travis-ci.org/marccarre/pam-servlet-filter)

# PAM Authentication Servlet Filter

Servlet filter to authenticate users using Basic Authentication and PAM (Linux Pluggable Authentication Modules).

It enables users to login using their Linux username and password.

## Dependencies:

1. Servlet container must be deployed on an operating system leveraging PAM (e.g.: Linux, macOS, etc.).
2. The `login` service must be installed, see also [this page](http://tldp.org/HOWTO/User-Authentication-HOWTO/x115.html).
3. The filter only depends on [libpam4j](https://github.com/kohsuke/libpam4j), which itself only depends on `net.java.dev.jna:jna`.
   No other 3rd party libraries are used or packaged in the "fat" JAR.

## Usage:

- add the JAR to your classpath, and
- optionally, and depending your web application, add the filter to your `web.xml`:

        <?xml version="1.0" encoding="UTF-8"?>
        <web-app xmlns="http://java.sun.com/xml/ns/javaee"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xsi:schemaLocation="http://java.sun.com/xml/ns/javaee
            http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd"
            version="3.0">
          
          <filter>
            <filter-name>pamAuthFilter</filter-name>
            <filter-class>com.carmatechnologies.servlet.PamAuthFilter</filter-class>
            <init-param>
              <param-name>realm</param-name>
              <param-value>NameOfYourApplication</param-value>
            </init-param>
          </filter>
          
          <filter-mapping>
            <filter-name>pamAuthFilter</filter-name>
            <url-pattern>/login.jsp</url-pattern>
          </filter-mapping>
        </web-app>

- N.B.: Basic authentication does *NOT* encrypt credentials, so be sure to use SSL/TLS.

## License:

Apache License Version 2.0

## Build:

- Compile, test and generate code coverage report:

        ./gradlew clean test

- Compile, package, test, generate code coverage reports, and publish them:

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
