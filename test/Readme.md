# Running tests

The unit test are written with [Mocha](https://mochajs.org/) and [Chai](https://www.chaijs.com/).

The following assumes all Node.js dependencies were installed via `npm install`.

Unless otherwise specified run all commands from the root of the repository.

## Running unit tests in a browser

Because of *CORS* opening the runner html page directly from the file system does not work.
A HTTP server is needed instead.

Below is an example with Node's [http-server](https://www.npmjs.com/package/http-server).

```PowerShell
# Start the server in the root directory of the repository
npx http-server . -c-1

# Open the test runner page
# http://localhost:8080/test/unittest/SpecRunner.html
```

## Running unit test in Node

> **Note**:
> As the Web Crypto API is not available in Node,
> the crypto implementation used differs from the one
> actually used in the add-on.

```PowerShell
# Run tests with
npm run test
# Or directly call mocha
npx mocha
```
