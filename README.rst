=================================
Exporting Non-Exportable RSA Keys
=================================

This project has been directly inspired by the follwing paper:

https://www.nccgroup.trust/globalassets/our-research/uk/whitepapers/exporting_non-exportable_rsa_keys.pdf

by Jason Geffner <jason.geffner@ngssecure.com> that can be found in the doc folder

The repo contain a Visual Stodio 2010 buildable project. The repo containe a build version and executable is in:

https://github.com/luipir/ExportNotExportablePrivateKey/blob/master/exportrsa/Debug/exportrsa.exe

How to use
~~~~~~~~~~

The code parse all system key stores and export in .pxf files all that have a RSA private key available.

Just run exportrsa.exe in a command shell
