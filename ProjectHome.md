The $USNJRNL logs changes to the NTFS file system. It will record that changes occurred to file data or metadata, but will not record the content of the changes. It is enabled by default in Vista and is optional in XP. All Windows version after XP have the capability to log changes.

On systems where the $USNJRNL is enabled, it can be found at the root of the NTFS partition in the $EXTEND folder. The file consists of two data streams, $USNJRNL $MAX and $USNJRNL $J. The $J data stream actually contains the transaction log entries that this tool is intended to parse.

This tool is intended to assist in computer forensics examinations of Windows systems. It will provide a description of the change, the filename, and the timestamp for each log entry.