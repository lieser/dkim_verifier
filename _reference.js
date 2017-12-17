// The .jsm extension does not work well together with IntelliSense.
// Even with reference and explicit @ts-check, the types of arguments are not detected.
//
// Workaround: 
// Creating symbolic links with .js extension for each .jsm file, and edit the js files.
//
// Powershell command for creating the links:
// DIR *.jsm | % { cmd /c "mklink modlinks\$($_.BaseName).js ..\$($_.BaseName).jsm" }

// ///<reference path="globals.d.ts" />
// ///<reference path="mozilla.d.ts" />
// ///<reference path="modules/AuthVerifier.d.ts" />

// ///<reference path="modules/ARHParser.jsm" />
// ///<reference path="modules/AuthVerifier.jsm" />
// ///<reference path="modules/dkimDMARC.jsm" />
// ///<reference path="modules/dkimKey.jsm" />
// ///<reference path="modules/dkimPolicy.jsm" />
// ///<reference path="modules/dkimVerifier.jsm" />
// ///<reference path="modules/DNSWrapper.jsm" />
// ///<reference path="modules/helper.jsm" />
// ///<reference path="modules/JSDNS.jsm" />
// ///<reference path="modules/libunbound.jsm" />
// ///<reference path="modules/libunboundWorker.jsm" />
// ///<reference path="modules/logging.jsm" />
// ///<reference path="modules/MsgReader.jsm" />
// ///<reference path="modules/SQLiteTreeView.jsm" />
