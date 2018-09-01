package com.web.config;

import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.webapp.AbstractConfiguration;
import org.eclipse.jetty.webapp.WebAppContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.jetty.JettyServerCustomizer;
import org.springframework.boot.web.embedded.jetty.JettyServletWebServerFactory;
import org.springframework.boot.web.embedded.tomcat.TomcatContextCustomizer;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.ConfigurableWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;

@Component
public class ServerConfig implements WebServerFactoryCustomizer<ConfigurableWebServerFactory> {

    @Value("${server.port}")
    private Integer securePort;

    @Override
    public void customize(ConfigurableWebServerFactory factory) {
        if (factory instanceof JettyServletWebServerFactory) {
            jettyServerConfig((JettyServletWebServerFactory) factory);
        } else {
            tomcatServerConfig((TomcatServletWebServerFactory) factory);
        }
    }

    private void jettyServerConfig(JettyServletWebServerFactory jettyServletWebServerFactory) {
        jettyServletWebServerFactory.addConfigurations(new HttpToHttpsJettyConfiguration());
        jettyServletWebServerFactory.addServerCustomizers((JettyServerCustomizer) server -> {
            HttpConfiguration http = new HttpConfiguration();
            http.setSecurePort(securePort);
            http.setSecureScheme("https");

            ServerConnector connector = new ServerConnector(server);
            connector.addConnectionFactory(new HttpConnectionFactory(http));
            connector.setPort(8080);

            server.addConnector(connector);
        });
    }

    private void tomcatServerConfig(TomcatServletWebServerFactory tomcatServletWebServerFactory) {
        tomcatServletWebServerFactory.addContextCustomizers((TomcatContextCustomizer) context -> {
            SecurityConstraint securityConstraint = new SecurityConstraint();
            securityConstraint.setUserConstraint("CONFIDENTIAL");
            SecurityCollection collection = new SecurityCollection();
            collection.addPattern("/*");
            securityConstraint.addCollection(collection);
            context.addConstraint(securityConstraint);
        });
        tomcatServletWebServerFactory.addAdditionalTomcatConnectors(createTomcatHttpConnector());
    }

    private Connector createTomcatHttpConnector() {
        Connector connector =
            new Connector("org.apache.coyote.http11.Http11NioProtocol");
        connector.setScheme("http");
        connector.setSecure(false);
        connector.setPort(8080);
        connector.setRedirectPort(securePort);
        return connector;
    }

    static class HttpToHttpsJettyConfiguration extends AbstractConfiguration {

        @Override
        public void configure(WebAppContext context) {
            Constraint constraint = new Constraint();
            constraint.setDataConstraint(2);

            ConstraintMapping constraintMapping = new ConstraintMapping();
            constraintMapping.setPathSpec("/*");
            constraintMapping.setConstraint(constraint);

            ConstraintSecurityHandler constraintSecurityHandler = new ConstraintSecurityHandler();
            constraintSecurityHandler.addConstraintMapping(constraintMapping);

            context.setSecurityHandler(constraintSecurityHandler);
        }

    }

}
