# ProFTPD module mod_clamav

The mod_clamav module is designed to prevent the upload of viruses,
trojans, and many more questionable items from even being uploaded.

The most current version of mod_clamav can be found at:

    http://www.ThrallingPenguin.com/

 ## Author
 Please contact Joseph Benden <joe at thrallingpenguin.com> with any
 questions, concerns, or suggesstions regarding this module.

 ##Directives
 * ClamAV

 ----

 <ClamAV>

 syntax: <ClamAV on>
 default: none
 context: all
 module: mod_clamav
 compatibility: 1.3.2

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


 Author: Joseph Benden
 Last Updated: 2012-05-05
 
