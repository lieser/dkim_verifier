# DKIM Verifier

This is an add-on for Mozilla Thunderbird that verifies DKIM signatures according to the RFC 6376.

Usage information can be found in the wiki at <https://github.com/lieser/dkim_verifier/wiki>.

## Packing the Add-on

This Add-on does not require any extra build steps.
All files in the repository are already in the format required by Thunderbird.
It only needs to be packed into an extension file.

Thunderbird extensions are packed as normal zip files.
Often the file extension `.xpi` is used,
but this is not a requirement.

### Manually

You can simply use your favorite zip tool to pack the content of the extension.

The required files are listed below under *Code structure*,
but for simplicity you can also pack the complete folder.
Just make sure the content is directly in the zip file and not in an extra root directory.

### Using Node.js

Requirements:

- [Node.js](https://nodejs.org)
- [Git](https://git-scm.com/) (must be in the path environment variable)

Run the following command to pack the extension:

```bash
npm run pack
```
