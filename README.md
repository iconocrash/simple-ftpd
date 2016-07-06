James Jilek

CS 450 - Intro Networking
Project 3 - Simplified FTP Server
Due. April 30th, 2008

To Compile:

Enter 'make' command to build,
or, to manually compile:
g++ server.cpp -o ftpserver

To Run:
./ftpserver [port [directory]]

The default port is 21.
The default directory is the current directory.

ftp -h and ftp -help will print out the same
message as above.

Status:

USER, PASS commands simply give "okay" replies for any input.
SYST replies standard UNIX repsonse.
CWD works.
PASV is working.
LIST is working.
RETR working.
STOR working.

Testing:

Program has been tested by running:
./ftpserver 21012 ./
and
telnet 127.0.0.1 21012
and
ftp 127.0.0.1 21012
on bert.cs.uic.edu.

