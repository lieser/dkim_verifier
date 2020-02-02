# Running tests

The unit test are written with [Mocha](https://mochajs.org/) and [Chai](https://www.chaijs.com/).

## Running unit tests in a browser

Because of *CORS* opening the runner html page directly from the file system does not work.
A HTTP server is needed instead.

Below is an example with Node's [http-server](https://www.npmjs.com/package/http-server).

```PowerShell
# Install the HTTP server, e.g. Node's http-server
npm install --save-dev http-server

# Start the server in the root directory of the repository
node node_modules/http-server/bin/http-server .

# Open the test runner page
# http://localhost:8080/test/unittest/SpecRunner.html
```

## Running unit test in Node

```PowerShell
# Install dependencies
npm install --save-dev mocha
npm install --save-dev chai
# Mocha currently has no native ESM support
# https://github.com/mochajs/mocha/pull/4038
npm install --save-dev esm

# Run tests
node node_modules/jasmine/bin/jasmine
node node_modules/mocha/bin/mocha --recursive
```
