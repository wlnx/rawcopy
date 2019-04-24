# rawcopy
Utility to dump or restore EFS-encrypted files.


If source file is EFS-encrypted, it will be dumped to destination.

If source file is not EFS-encrypted, it is considered to be a dump and utility will restore it to destination.

If EFS key pair is not installed, SeBackupPrivilege and SeRestorePrivilege may be required.

If this is the case, run rawcopy as backup operator or local administrator.


Usage:

- rawcopy [/f] source destination

- rawcopy /?


Parameters:

- **/f**          If destination file exists it will be overwritten.

- **source**      File to be dumped or restored from. File must exist. If source is a directory, operation fails. Wildcards are not accepted.

- **destination** File to be dumped or restored to. If destination is a directory, filename of source preserved.
