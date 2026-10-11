FROM maven:3.9.16-amazoncorretto-25-al2023 AS build

WORKDIR /opt/opik-auth
COPY pom.xml lombok.config ./
RUN mvn -B dependency:go-offline
COPY src ./src
ENV MAVEN_OPTS="-Xmx768m"
RUN mvn -B clean package -Dmaven.test.skip=true

###############################
FROM amazoncorretto:25.0.4-al2023

LABEL org.opencontainers.image.title="Opik Auth"
LABEL org.opencontainers.image.description="Self-hosted login / RBAC service for Opik (react-service auth protocol)"

# DL3033: AL2023 packages track a rolling security channel
# hadolint ignore=DL3033
RUN yum install -y --allowerasing shadow-utils curl && yum clean all && rm -rf /var/cache/yum

WORKDIR /opt/opik-auth
COPY --chown=1001:1001 config.yml ./
COPY --from=build --chown=1001:1001 /opt/opik-auth/target/opik-auth.jar ./

RUN chmod 1777 /tmp
USER 1001:1001
EXPOSE 8080 8081
ENV JAVA_OPTS="-XX:MaxRAMPercentage=60"

# Migrations also run automatically on `server` (autoMigrate); the explicit step keeps failures obvious.
CMD ["bash", "-c", "java $JAVA_OPTS -jar opik-auth.jar db migrate config.yml && exec java $JAVA_OPTS -jar opik-auth.jar server config.yml"]
