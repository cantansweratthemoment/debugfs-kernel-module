# debugfs-kernel-module
A kernel-level program collects information on the kernel side, transfers it to the user level, and outputs it in a human-readable form. The user-level program receives command line arguments as output, which allow it to identify the necessary path for the target structure. The structures are printed to standard output.

**Interface:** `debugfs`
**Structures:** `vfsmount, page`
