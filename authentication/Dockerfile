FROM maven:3.8.6-eclipse-temurin-17 as build

WORKDIR /app

COPY pom.xml .

COPY lib/ ./lib

COPY src/ ./src

RUN mvn install:install-file -Dfile=lib/AthenaJDBC42.jar -DgroupId=Athena -DartifactId=AthenaJDBC42 -Dversion=2.0.31.1001 -Dpackaging=jar

RUN mvn -e -f . package -Dmaven.test.skip=true

#runtime -------------------------------------------

FROM eclipse-temurin:17-jdk-alpine as runtime

USER 1001

WORKDIR /app

COPY --from=build /app/target/*.jar /app/api.jar

ENTRYPOINT ["java", "-jar", "/app/api.jar"]
