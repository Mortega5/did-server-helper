# 📜 DID Server Helper (`did-server-helper`)

## 🌟 Project Purpose

This project acts as an auxiliary service supporting Decentralized Identifier (DID) infrastructure and verifiable credentials.

### 🔑 Public Key Exposure (JWKS)

The service exposes its signing and verification public keys via the standardized [JSON Web Key Set (JWKS)](https://datatracker.ietf.org/doc/html/rfc7517) endpoint.

* **Endpoint:** `/.well-known/jwks`
* **Function:** Allows other parties (verifiers) to download the public keys required to authenticate the signatures of DIDs or credentials issued by this service.

## 🛠️ Configuration (Prerequisites)

To develop, build, and deploy this project, you need:

* **Java 21**
* **Maven 3.8+**.
* **Docker** (for image compilation and deployment).

### ⚙️ Environment Configuration

The application is primarily configured via `application.yml` or environment variables. The JWKS configuration block is critical for exposing the public key metadata.

| Variable/Property | Configuration Source | Description | Example |
| :--- | :--- | :--- | :--- |
| `MICRONAUT_SERVER_PORT` | Environment / `application.yml` | The port on which the service listens. | `8080` |
| **`JWKS_KEY_ID`** | Environment / `jwks.key-id` | **Key Identifier (`kid`)** exposed in the JWKS endpoint. | `did-server-key-01` |
| **`JWKS_ALGORITHM`** | Environment / `jwks.algorithm` | The cryptographic algorithm used for signing and JWKS. | `ES256` |
| **`JWKS_PRIVATE_KEY_PATH`** | Environment / `jwks.private-key-path` | **Local path to the private key file (PEM format)** used for signing. | `./certs/private-key.pem` |

**Note on JWKS:** The `JWKS_PRIVATE_KEY_PATH` variable assumes the key file is accessible by the application at runtime. For Docker deployment, ensure the file is copied into the container.

```yaml
# application.yml
micronaut:
  server:
    port: 8080 # Configures the server listening port

jwks:
  # Key identifier for the public key
  key-id: did-server-key-01
  # Cryptographic algorithm used
  algorithm: ES256
  # Local path to the private key file (PEM format)
  private-key-path: ./certs/private-key.pem
```
-----

## ⚙️ Environment Configuration

## 🏗️ Building the Project

### 1\. Standard Build (JAR)

This command compiles the application and generates the standard JAR file in `target/`.

```bash
mvn clean package
```

## 2\. Docker Image Deployment (Jib)

The Jib plugin configuration uses three essential Maven properties (defined in your `pom.xml` or passed as command-line arguments) to determine the image destination:

| Maven Property | Purpose | Example Value                          |
| :--- | :--- |:---------------------------------------|
| **`${image.registry}`** | **The host address of your Docker registry.** | `registry.hub.docker.com` or `ghcr.io` |
| **`${image.repository}`** | **The namespace or organization name** within the registry where the image will be stored. | `superuser5`                           |
| **`${project.artifactId}`** | **The name of the image.** This is usually derived automatically from your `pom.xml`. | `did-server-helper`                    |

**The final image target is constructed as:** `${image.registry}/${image.repository}/${project.artifactId}`.

### Prerequisite: Docker Credentials

You must configure your Docker registry credentials.

### Deployment Steps

To generate the standard image and push it to your registry with the version tag (`${project.version}`):

```bash
# This compiles the code and then Jib builds and pushes the Docker image (based on the JVM).
mvn clean install -Pdocker
```

-----

## 🧪 Running Tests

Your project uses **JUnit 5** with the **Surefire** plugin for unit tests and the **Failsafe** plugin for integration tests.

### 1\. Unit Tests Only

Run only the `test` phase (unit tests):

```bash
mvn test
```

### 2\. Full Test Suite (Unit & Integration)

Run the `verify` phase, which ensures that both unit tests and integration tests (`*IT.java`) pass:

```bash
mvn verify
```

### 3\. Code Format Verification (Spotless)

To ensure your code adheres to the defined formatting rules (typically run before a commit or push):

```bash
mvn spotless:check
```