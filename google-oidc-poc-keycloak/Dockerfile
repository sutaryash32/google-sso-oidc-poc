# Keycloak image with the tenant-resolver plugin built in, so nothing has to be compiled on the host.
#
# Stage 1 compiles tenant-spi (and runs its unit tests: a failing test fails the image build).
# Stage 2 is stock Keycloak with the resulting jar in providers/. `start-dev` installs it on startup.
#
# Rebuild after changing tenant-spi/:   docker compose build keycloak
# syntax=docker/dockerfile:1

FROM maven:3.9-eclipse-temurin-17 AS spi
WORKDIR /build
COPY tenant-spi/pom.xml .
RUN --mount=type=cache,target=/root/.m2 mvn -q -B dependency:go-offline
COPY tenant-spi/src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -q -B package

FROM quay.io/keycloak/keycloak:24.0.3
COPY --from=spi /build/target/tenant-spi.jar /opt/keycloak/providers/tenant-spi.jar
