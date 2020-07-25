# Running tests

The unit test are written with [Mocha](https://mochajs.org/) and [Chai](https://www.chaijs.com/).

## Running unit tests in a browser

> **Note**:
> The unit test do currently not have a fake implementation of the storage API.
> Instead they use a preference implementation that differs from the one
> actually used in the add-on.

Because of *CORS* opening the runner html page directly from the file system does not work.
A HTTP server is needed instead.

Below is an example with Node's [http-server](https://www.npmjs.com/package/http-server).

```PowerShell
# Install the HTTP server, e.g. Node's http-server
npm install --save-dev http-server

# Start the server in the root directory of the repository
npx http-server .

# Open the test runner page
# http://localhost:8080/test/unittest/SpecRunner.html
```

## Running unit test in Node

> **Note**:
> As the Web Crypto API is not available in Node,
> the crypto implementation used differs from the one
> actually used in the add-on.

```PowerShell
# Install dependencies
npm install --save-dev mocha
npm install --save-dev chai

npm install --save-dev sinon
npm install --save-dev webextensions-api-fake

# Run tests
npx mocha --reporter dot
```
