# Source snapshot



Original local source files are unchanged. This private backup excludes credentials, signing keys, local configuration, dependencies, build caches, runtime data, and unrelated research/old backup folders. No build or functionality test was run as part of this upload.

## Excluded paths

- `BioAppLock/bin/`
- `BioAppLock/Models/`
- `BioAppLock/obj/`

## Source completeness repair

The required `Models/AppProtectionModels.cs` source was restored after an overly broad model-data exclusion. An isolated .NET 10 Release build with that file passed with 0 warnings and 0 errors. The local original project was not edited.
