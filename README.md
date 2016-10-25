## Implement a Sandbox using ptrace

This is a small sandbox to limit the number of allowed syscalls for a process.

### Configuration file

The configuration file contains one specification per line. Each specification contains a permission and one glob pattern (see wiki and glob(3) man page). The fields are separated by any number of spaces or tabs. The permission is a 3-bit binary digit, representing in order read, write, and execute permissions. See chmod(1). Therefore,

111 foo.txt
is full permission and
000 foo.txt
is complete denial.
It is possible that more than one specification matches a given file name. In such a case, the last match is the one that holds. For example, suppose the following two-line configuration file.

000 /usr/foo/*
110 /usr/foo/bar
The file "/usr/foo/bar" matches both lines. Therefore, the last line (110) holds. This is useful for denying access to all files in directory except for an enumerated few.
