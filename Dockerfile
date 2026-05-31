FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

RUN addgroup -S spring && adduser -S spring -G spring

COPY target/*.jar app.jar

RUN chown spring:spring app.jar

USER spring:spring

EXPOSE 8010

HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8010/actuator/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]