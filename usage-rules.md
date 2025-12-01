# Usage Rules for NFTables.Port Project

## Test Principles
* never write tests which hook to live network tables like input, output, forward, nat, etc.  Always use isolated tables.

## Permission
* there is no sudo access, always ask to run a sudo <command> externally