
[![Gitter Chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter Chat")
# IBM X-Force Exchange Relay (Cisco Hosted)

A Cisco SecureX Concrete Relay implementation using [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com) as a third-party Cyber Threat Intelligence service provider.

The Relay itself is just a simple application written in Python that can be easily packaged and deployed.  This relay is now Cisco Hosted and no longer requires AWS Lambda.

The code is provided here purely for educational purposes.

## Rationale

- We need an application that will translate API requests from SecureX Threat Response to the third-party integration, and vice versa.
- We need an application that can be completely self contained within a virtualized container using Docker.

## Testing (Optional)

If you want to test the application you will require Docker and several dependencies from the [requirements.txt](requirements.txt) file:
```
pip install --upgrade --requirement requirements.txt
```

You can perform two kinds of testing:

- Run static code analysis checking for any semantic discrepancies and [PEP 8] https://www.python.org/dev/peps/pep-0008/) compliance:

  `flake8 code`

- Run the suite of unit tests and measure the code coverage:

  `coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report`

If you want to test the live Lambda you may use any HTTP client (e.g. Postman),
just make sure to send requests to your Lambda's `URL` with the `Authorization`
header set to `Bearer <JWT>`.

**NOTE.** If you need input data for testing purposes you can use data from the
[observables.json](observables.json) file.

### Building the Docker Container
In order to build the application, we need to use a `Dockerfile`.  

 1. Open a terminal.  Build the container image using the `docker build` command.

```
docker build -t tr-05-ibm-xforce-exchange
```

 2. Once the container is built, and an image is successfully created, start your container using the `docker run` command and specify the name of the image we have just created.  By default, the container will listen for HTTP requests using port 9090.

```
docker run -dp 9090:9090 --name tr-05-ibm-xforce-exchange tr-05-ibm-xforce-exchange
```

 3. Watch the container logs to ensure it starts correctly.

```
docker logs tr-05-ibm-xforce-exchange
```

 4. Once the container has started correctly, open your web browser to http://localhost:9090.  You should see a response from the container.

    curl http://localhost:9090

## Implementation Details

### Implemented Relay Endpoints

- `POST /health`
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Authenticates to the underlying external service to check that the provided
  credentials are valid and the service is available at the moment.

- `POST /deliberate/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Makes a series of requests to the underlying external service to query for
  some cyber threat intelligence data on each supported observable.
  - Maps the fetched data into appropriate CTIM entities.
  - Returns a list per each of the following CTIM entities (if any extracted):
    - `Verdict`.

- `POST /observe/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Makes a series of requests to the underlying external service to query for
  some cyber threat intelligence data on each supported observable.
  - Maps the fetched data into appropriate CTIM entities.
  - Returns a list per each of the following CTIM entities (if any extracted):
    - `Verdict`,
    - `Judgement`,
    - `Indicator`,
    - `Sighting`,
    - `Relationship`.

- `POST /refer/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Builds a search link per each supported observable to pivot back to the
  underlying external service and look up the observable there.
  - Returns a list of those links.
  
- `POST /version`
  - Returns the current version of the application.

### Supported Types of Observables

- `ip`
- `ipv6`
- `domain`
- `md5`
- `sha1`
- `sha256`

### JWT Payload Structure

```json
{
  "key": "<IBM_X-FORCE_EXCHANGE_API_KEY>",
  "password": "<IBM_X-FORCE_EXCHANGE_API_PASSWORD>"
}
```

### Supported Environment Variables

- `CTR_ENTITIES_LIMIT`
  - Restricts the maximum number of CTIM entities of each type returned in a
  single response per each requested observable.
  - Applies to the following CTIM entities:
    - `Judgement`,
    - `Indicator`,
    - `Sighting`.
  - Must be a positive integer. Defaults to 100 (if unset or incorrect).
  Has the upper bound of 1000 to avoid getting overwhelmed with too much data,
  so any greater values are still acceptable but also limited at the same time.
  

### CTIM Mapping Specifics

Each X-Force `associated collection` generates a CTIM `Sighting` and `Indicator` 
linked with a `member-of` `Relation`.

Data from X-Force `report` is used to generate
following CTIM entities depending on the observable type.
 
For `URL` and `Domain`:
   - a `Verdict` based on `report` `.result.score`
   - a `Judgement` based on `report` `.result.score`
   - an `Indicator` for each `category` in `report` `.result.cats`
   - a `Sighting` for each `category` in `report` `.result.cats`
   - a `sighting-of` `Relation` for `Sighting` and `Indicator`  created from one `category`

For `IP` and `IPv6`:
   - a `Verdict` based on `report` `.score`
   - a `Judgement` for each `category` in `report` `.cats`
   - an `Indicator` for each `category` in `report` `.cats`
   - a `Sighting` for each `category` in `report` `.cats`
   - a `based-on` `Relation` for `Sighting` and `Judgement`  created from one `category`
   - a `based-on` `Relation` for `Judgement` and `Indicator`  created from one `category`
  
For `MD5`, `SHA1` and `SHA256`:
   - a `Verdict` based on `report` `malware.risk`
   - a `Judgement` based on `report` `malware.risk`
 
