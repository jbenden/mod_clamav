# ProFTPD module mod_clamav

The mod_clamav module is designed to prevent the upload of viruses,
trojans, and many more questionable items from even being uploaded.

Additional information may be found at the following URL:

    http://www.thrallingpenguin.com/resources/mod_clamav.htm

## Author

Please contact Joseph Benden (joe at thrallingpenguin.com) with any
questions, concerns, or suggesstions regarding this module.

## Directives

* ClamAV
* ClamFailsafe
* ClamServer
* ClamPort
* ClamStream
* ClamMinSize
* ClamMaxSize
 
----

* ClamAV
 * syntax: ClamAV on
 * default: none
 * context: all
 * module: mod_clamav
 * compatibility: 1.3.2

The ClamAV directive will configure if the Mod_Clamav's virus scanning
and virus removal features are active. If no ClamAV directive is
configured, then the module will do no virus scanning.

* ClamFailsafe
 * syntax: ClamFailsafe boolean
 * default: false
 * context: all
 * module: mod_clamav
 * compatibility: 0.13rc2

The ClamFailsafe directive will configure if Mod_Clamav's inability to
scan a file, for any reason, will cause the failure of the file to
upload. If no ClamFailsafe directive is configured, then the module
will accept files that may not have been completely scanned by Clamd.

* ClamServer
 * syntax: ClamServer hostname/ip
 * default: none
 * context: server config,virtualhost,global,directory
 * module: mod_clamav
 * compatibility: 0.6 of mod_clamav

The ClamServer directive will configure the hostname/IP address used
to connect to the Clamd daemon process. If no ClamServer directive is
configured, then the module will do no TCP Clamd scanning.

Please see the ClamStream directive if using a different host for
Clamd than the ProFTPd server.

* ClamPort
 * syntax: ClamPort integer
 * default: 3310
 * context: server config,virtualhost,global,directory
 * module: mod_clamav
 * compatibility: 0.6 of mod_clamav

The ClamPort directive will configure the TCP port used to connect to
the Clamd daemon process. If no ClamPort directive is configured,
then the module will use the Clamd default TCP port of 3310.

* ClamStream
 * syntax: ClamStream boolean
 * default: off
 * context: server config,virtualhost,global,directory
 * module: mod_clamav
 * compatibility: 0.13rc3

The ClamStream directive will enable the streaming of the uploaded
file contents to the Clamd server using the INSTREAM protocol. This
directive should be used when the Clamd server is on a different
host than the ProFTPd server. If no ClamStream directive is
configured, then the module will use the SCAN Clamd protocol.
 
* ClamMinSize
 * syntax: ClamMinSize integer [units]
 * default: 0
 * context: server config,virtualhost,global,directory
 * module: mod_clamav
 * compatibility: 0.10 of mod_clamav

The ClamMinSize directive will configure the minimum file size for
scanning. If the file size is smaller than this value, then the module
will do no scanning.

The given integer (may be an unsigned long) is the number of bytes for
the directive, and is followed by a units specifier of
(case-insensitive) "Gb" (Gigabytes), "Mb" (Megabytes), "Kb"
(Kilobytes), or "B" (Bytes). The given integer of bytes is multiplied
by the appropriate factor. A value of zero (0) disables this
directive.
 
* ClamMaxSize
 * syntax: ClamMaxSize integer [units]
 * default: 0
 * context: server config,virtualhost,global,directory
 * module: mod_clamav
 * compatibility: 0.10 of mod_clamav

The ClamMaxSize directive will configure the maximum file size for
scanning. If the file size is larger than this value, then the module
will do no scanning.

The given integer (may be an unsigned long) is the number of bytes for
the directive, and is followed by a units specifier of
(case-insensitive) "Gb" (Gigabytes), "Mb" (Megabytes), "Kb"
(Kilobytes), or "B" (Bytes). The given integer of bytes is multiplied
by the appropriate factor. A value of zero (0) disables this
directive.
 
## Installation

To install mod_clamav, copy the mod_clamav.[ch] files into:

    proftpd-dir/contrib/

after unpacking the proftpd source code. For including mod_clamav as
a statically linked module:

    ./configure --with-modules=mod_clamav

To build mod_clamav as a DSO module

    ./configure --enable-dso --with-shared=mod_clamav

Then follow the usual steps:

    make
    make install

For those with an existing ProFTPD installation, you can use the prxs
tool to add mod_clamav, as a DSO module, to your existing serverL

    prxs -c -i -d mod_clamav.c

## Example Configuration

Tip: Enable HiddenStore for virus scanning to take place in the background.

    <IfModule mod_clamav.c>
       ClamAV on
       ClamServer localhost
       ClamPort 3310
    </IfModule>

