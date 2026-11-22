FROM eclipse-temurin:17-jdk AS build
WORKDIR /app

COPY gradlew settings.gradle* build.gradle* gradle.properties* ./
COPY gradle gradle
RUN chmod +x gradlew
RUN ./gradlew dependencies --no-daemon > /dev/null

COPY src src
RUN ./gradlew bootJar --no-daemon

FROM eclipse-temurin:17-jre
WORKDIR /app
RUN useradd -r -u 1001 app
COPY --from=build /app/build/libs/*.jar app.jar
USER app
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]