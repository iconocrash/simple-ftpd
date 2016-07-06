/*
* James Jilek
* CS 450 - Project 3
* Simplified FTP Server
* Spring 2008
*/


/* C Standard Library Headers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

/* UNIX Headers */
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <dirent.h>

/* Headers for Internet Communication
   with Berkeley Sockets */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <assert.h>

/* Server settings */

#define FTP_DEFAULT_SERVER_PORT			21	// default port we listen on for FTP
#define FTP_MAX_BACKLOG_CONNECTIONS		10	// how many connection can be held in the connection queue

/* FTP commands */

enum FTPCmdsEnum
{
	FTPCMD_USER = 0,
	FTPCMD_PASS,
	FTPCMD_SYST,
	FTPCMD_CWD,
	FTPCMD_PASV,
	FTPCMD_LIST,
	FTPCMD_RETR,
	FTPCMD_STOR,
	FTPCMD_TYPE,
	FTPCMD_QUIT
};

char* ftpCmds[] =
{
	"USER",
	"PASS",
	"SYST",
	"CWD",
	"PASV",
	"LIST",
	"RETR",
	"STOR",
	"TYPE",
	"QUIT"
};

enum ReplyEnum
{
	REPLY_220_BEGIN_SESSION = 0,	// initial server reply message
	
	/* USER, PASS, and SYST */
	REPLY_331_USERNAME_OK,
	REPLY_230_PASS_ACCEPT,		// this is usually used as the welcome message too
	REPLY_215_SYST_RESPONSE,
	
	/* CWD */
	REPLY_250_DIRCHANGE_SUCCESS,
	REPLY_550_DIRCHANGE_FAILURE,
	
	/* PASV */
	REPLY_227_PASSIVE_MODE,
	
	/* LIST */
	REPLY_150_SENDING_DIR_LIST,
	REPLY_226_DIR_SEND_OK,

	/* RETR */
	REPLY_150_OPEN_BINARY_DATA_CONNECTION,
	REPLY_226_FILE_SEND_OK,
	REPLY_550_FILE_NOT_FOUND,
	
	/* STOR */
	REPLY_150_READY_FOR_TRANSFER,
	REPLY_226_RECEIVED_FILE_CLOSING_CONNECTION,
	REPLY_550_COULDNT_OPEN_FILE,
	
	/* TYPE */
	REPLY_200_TYPE_SET_TO_I,
	REPLY_200_TYPE_SET_TO_A,
	
	REPLY_221_END_SESSION,
	
	REPLY_500_UNKNOWN_COMMAND
};

char* replies[] =
{
	"220 Welcome to JJ's FTPServ v4.2.\r\n",
	
	"331 User name okay, proceed.\r\n",
	"230 Password accepted, proceed.\r\n",
	"215 UNIX Type: L8\r\n",
	"250 Directory successfully changed.\r\n",
	"550 Failed to change directory.\r\n",
	"227 Entering Passive Mode %s\r\n", // enter in IP-port string
	
	"150 Here comes the directory listing.\r\n",
	"226 Directory send OK.\r\n",

	"150 Opening BINARY mode data connection for %s (%i bytes).\r\n", // filename and size in bytes
	"226 File send OK.\r\n",
	"550 Requested action not taken.\r\n",
	
	"150 File status okay; about to open data connection.\r\n",
	"226 File send OK.\r\n", // "226 Closing data connection..\r\n"
	"550 Requested action not taken.\r\n",
	
	"200 Type set to I.\r\n",
	"200 Type set to A.\r\n",
	
	"221 Goodbye.\r\n",
	
	"500 Unknown Command.\r\n",
	
	/* ----- unused ----- */
	"426 Connection closed; transfer aborted.\r\n"
	"500 Illegal Command Syntax.\r\n",
	"331-Welcome\n331 Login successful.\r\n",
	"530 Please login with USER and PASS.\r\n"
};

void ExitError(char* errorMsg, int exitCode = EXIT_FAILURE)
{
	printf("Error: %s \n", errorMsg);
	perror("Errno Description");
	printf("Exiting.\n\n");
	exit(exitCode);
}

/* Try to get the host machine's public internet IP address. There may be
multiple public IP's so just use the first one that's isn't 127.* or 192.*
or any other private IP range. If no non-local IP's exist then return a
local IP. */
void TryToGetPublicHostIPAddr( struct sockaddr_in * hostIPAddr )
{
	//char localHostName[MAXHOSTNAMELEN];
	//gethostname(localHostName, MAXHOSTNAMELEN);
	//struct hostent* hostEntry = gethostbyname(localHostName);
	//*hostIPAddr = *(struct in_addr *)*hostEntry->h_addr_list;// TODO: make sure the first item in the list isn't 127.0.0.1 or something
}

int CreateListenSocket(int maxBacklogConnections, int listenPort, bool dynamicPort = false, bool allowAddrInUseBind = false)
{
	/* binding with a port value of 0 in the sock address
	struct will bind to a dynamic port */
	if (dynamicPort)
	{
		listenPort = 0;
	}
	
	/* create our listentng socket */
	int listenSocket = socket(AF_INET, SOCK_STREAM, 0);	// create socket for TCP/IP connection
	if (listenSocket == -1) 				// socket() returns -1 upon failure
		ExitError("Failed to create listening socket.");
	
	if (allowAddrInUseBind)
	{
		/* this alleviates "address already in use" errors when the kernel has
		not gotten around to freeing the socket on the specified port from 
		previous instances of this or other processes */
		int yes = 1; // apparently for setting socket options on Solaris this would need to be '1'
		if ( setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 )
			ExitError("Could not set socket option.");
	}
	
	/* fill in the local address struct for binding to */
	struct sockaddr_in localAddr;					// local machine internet address information
	localAddr.sin_family = AF_INET;					// host byte order
	localAddr.sin_port = htons(listenPort);				// port to listen on, network byte order
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);			// fill with the host machine's IP
	//localAddr.sin_addr.s_addr = inet_addr("127.0.0.1");		// another way
	memset(localAddr.sin_zero, 0, sizeof(localAddr.sin_zero));	// zero the sin_zero field
	
	/* bind the listen socket to the address and port */
	if ( bind(listenSocket, (struct sockaddr *)&localAddr, sizeof(localAddr)) == -1 )
		ExitError("Could not bind address to socket.");
	
	/* set the socket to listen for connections */
	if ( listen(listenSocket, maxBacklogConnections) == -1 )
		ExitError("Could not listen and on the address and port.");
	
	return listenSocket;
}

int AcceptConnectionFromListenSocket(int listenSocket, struct sockaddr_in * remoteAddr)
{
	/* Accept the first connection on the backlog queue. accept() blocks if
	there are no connections in the queue. */
	socklen_t sinSize = sizeof(sockaddr_in);
	int acceptSocket = accept(listenSocket, (struct sockaddr *)remoteAddr, &sinSize);
	if (acceptSocket == -1)
		ExitError("Failure creating socket for accepting connection.");
	
	return acceptSocket;
}

/* Get the next command on the control connection socket
(blocking until it comes), and parses the command */
int GetControlConnectionCmd(int controlSocket, char msgBuf[], int& msgBufLen, int MSG_BUF_MAX_SIZE, char* cmdTokens[], int& numCmdTokens)
{
	/* Receive the next message on the control connection (blocks until next message is received). */
	
	if ( ( msgBufLen = recv(controlSocket, msgBuf, MSG_BUF_MAX_SIZE, 0 ) ) == -1 )
		ExitError("Error receiving control connection data.");
	if ( msgBufLen == 0 ) // recv() returns 0 if the remote side has closed the connection */
		return 1;
	
	printf("Received Data:");
	for (int i = 0; i < msgBufLen; i++)
	{
		//printf("byte %i: " i);
		printf(" '");
		if (msgBuf[i] == '\n')
			printf("<LF>");
		else if (msgBuf[i] == '\r')
			printf("<CR>");
		else if (msgBuf[i] < 32 || msgBuf[i] > 126)
			printf("<0x%x>", msgBuf[i]);
		else
			putchar(msgBuf[i]);
		printf("'");
	}
	printf(".\n");
	
	/* Get rid of the trailing CR LF for processing the commands */
	
	msgBuf[msgBufLen-2] = '\0';
	msgBufLen--;
	
	printf("Command: %s\n", msgBuf);
	
	/* Tokenize strings */
	
	char* token = strtok(msgBuf, " ");
	if (token == NULL) // found no delimiter to tokenize
	{
		/* if there are no space delimiters it
		must be a one word command */
		cmdTokens[0] = msgBuf;
		numCmdTokens = 1;
	}
	else
	{
		/* there are space delimeters so we add all
		the tokens to our array of tokens */
		cmdTokens[0] = token;
		numCmdTokens = 1;
		while ( (token = strtok(NULL, " ")) != NULL )
		{
			cmdTokens[numCmdTokens] = token;
			numCmdTokens++;
		}
	}
	
	printf("Command tokens:");
	for (int i = 0; i < numCmdTokens; i++)
	{
		printf(" \"");
		printf("%s", cmdTokens[i]);
		printf("\"");
	}
	printf(".\n");
	
	return 0;
}

enum FileInfoEnum
{
	FILEINFO_ERROR = -1,
	FILEINFO_DOESNOTEXIST = 0,
	FILEINFO_REGULARFILE,
	FILEINFO_DIR,
	FILEINFO_SPECIALFILE
};

/* Get file info about a certain file (directories count as files). 
Note that "." and ".." are considering special files, not dirs. */
FileInfoEnum GetFileInfo(char* path)
{
	FileInfoEnum fileInfo;
	int fileDesc = open(path, O_RDONLY);
	if (fileDesc == -1)
	{
		if (errno = ENOENT)
			fileInfo = FILEINFO_DOESNOTEXIST;
		else
			fileInfo = FILEINFO_ERROR;
		
		close(fileDesc);
		return fileInfo;
	}
	
	struct stat statBuf;
	if ( fstat(fileDesc, &statBuf) != 0 )
		ExitError("fstat() failed to get file info.");
	
	if ( S_ISDIR(statBuf.st_mode) )
		fileInfo = FILEINFO_DIR;
	else if ( S_ISREG(statBuf.st_mode) )
		fileInfo = FILEINFO_REGULARFILE;
	else
		fileInfo = FILEINFO_SPECIALFILE;
	
	close(fileDesc);
	return fileInfo;
}

/* Test code for the above function */
void TestGetFileInfo()
{
	printf("Testing GetFileInfo()...\n");
	printf("FileInfo() test 1: %i.\n", GetFileInfo(".."));
	printf("FileInfo() test 2: %i.\n", GetFileInfo("testdir"));
	printf("FileInfo() test 3: %i.\n", GetFileInfo("README"));
	printf("FileInfo() test 4: %i.\n", GetFileInfo("dsjfsdfbsdfhsb"));
	printf("FileInfo() test 5: %i.\n", GetFileInfo("/dev/null"));
	printf("FileInfo() test 6: %i.\n", GetFileInfo("."));
	printf("Done testing.\n");
}

/* Take in a directory path and add a trailing slash if there is not one */
void AddTrailingSlashIfNeeded(char * directoryPath)
{
	int len = strlen( directoryPath );
	if ( directoryPath[len-1] != '/' )
	{
		directoryPath[len] = '/';
		directoryPath[len+1] = '\0';
	}
	else // already has a trailing slash
		return;
}

/* Get the size of the file in bytes, return -1 if there
was a problem opening the file (probably doesn't exist) */
int GetFileSize(char* fileName)
{
	struct stat statBuf;
	if ( stat(fileName, &statBuf) != 0 )
		return -1; // could get perror too
	return statBuf.st_size;
}

/* Globals for the FTP session. */

// Message buffer for sending and receiving
const int MSG_BUF_MAX_SIZE = 1024;
char msgBuf[MSG_BUF_MAX_SIZE];
int msgBufLen = -1;

char dir[PATH_MAX]; 	// always maintain a trailing slash on the directory
char pathBuf[PATH_MAX];	// temp buffer for working with directories and files

// Data holder for parsed commands */
const int MAX_CMD_TOKENS = 200;
char* cmdTokens[MAX_CMD_TOKENS];
int numCmdTokens;

// forward declaration
void FTPDataTransferSession(int controlSocket, int dataTransferSessionSocket);

void FTPSession(int controlSocket, char* inputRootDir, struct sockaddr_in remoteAddr)
{
	
	strcpy( dir, inputRootDir ); // copy into new buffer so we can make the directory string larger if needed
	AddTrailingSlashIfNeeded( dir ); // make sure we have a trailing slash on the file
	char properRootDir[PATH_MAX];
	strcpy( properRootDir, dir );
	
	/* Test to see if the directory to serve exists */	
	if ( GetFileInfo(dir) == FILEINFO_DOESNOTEXIST )
		ExitError("Failed to open directory to serve.");
	
	/* Reply 220 to user upon connection */
	if ( send(controlSocket, replies[REPLY_220_BEGIN_SESSION], strlen(replies[REPLY_220_BEGIN_SESSION ]), 0) == -1 )
		ExitError("Error sending reply.");
	
	while (1)
	{
		printf("Serving Directory: <%s>.\n", dir);
		
		int ret;
		
		/* Receive and parse the next command
		over the socket from the user. */
		ret = GetControlConnectionCmd(
			controlSocket,
			msgBuf, msgBufLen, MSG_BUF_MAX_SIZE,
			cmdTokens, numCmdTokens
		);
		if (ret == 1) // user has closed connection
			break; // break out of loop and end session
		
		/* Do the specified command */
		
		/* USER command - We're not doing authentication. Just reply
		with a normal username okay message */
		if (strcmp(cmdTokens[0], ftpCmds[FTPCMD_USER]) == 0)
		{
			printf("Receivied USER command.\n");
			send(controlSocket, replies[REPLY_331_USERNAME_OK], strlen(replies[REPLY_331_USERNAME_OK]), 0);
		}
		/* PASS command - Like with PASS we're not doing
		authentication. Just reply with a normal username okay
		message */
		else if (strcmp(cmdTokens[0], ftpCmds[FTPCMD_PASS]) == 0)
		{
			printf("Receivied PASS command.\n");
			send(controlSocket, replies[REPLY_230_PASS_ACCEPT], strlen(replies[REPLY_230_PASS_ACCEPT]), 0);
		}
		/* SYST command - Give a typical UNIX system response */
		else if (strcmp(cmdTokens[0], ftpCmds[FTPCMD_SYST]) == 0)
		{
			printf("Receivied SYST command.\n");
			send(controlSocket, replies[REPLY_215_SYST_RESPONSE], strlen(replies[REPLY_215_SYST_RESPONSE]), 0);
		}
		/* CWD command - Print out the current working directory. */
		else if (strcmp(cmdTokens[0], ftpCmds[FTPCMD_CWD]) == 0)
		{
			printf("Receivied CWD command.\n");
			
			char* dirToChangeTo = cmdTokens[1];
			
			if ( strcmp( "." , dirToChangeTo ) == 0 )
			{
				// change to current directory, so don't change anything and reply with success
				send(controlSocket, replies[REPLY_250_DIRCHANGE_SUCCESS], strlen(replies[REPLY_250_DIRCHANGE_SUCCESS]), 0);
				continue;
			}
			
			/* handle ".." CWD command */
			if ( strcmp( ".." , dirToChangeTo ) == 0 )
			{
				int len = strlen( dir );
				assert( dir[len-1] == '/' ); // all dirs should have slash at end
				if ( strcmp( dir , properRootDir ) == 0 )
				{
					printf("User tried to go above root directory.\n");
					send(controlSocket, replies[REPLY_550_DIRCHANGE_FAILURE], strlen(replies[REPLY_550_DIRCHANGE_FAILURE]), 0);
					continue;
				}
				/* chomp the last dir off the end */
				for (int i = len - 2;  ; i--)
				{
					assert ( i > 0 );
					if (dir[i] == '/')
					{
						dir[i+1] = '\0';
						break;
					}
				}
				send(controlSocket, replies[REPLY_250_DIRCHANGE_SUCCESS], strlen(replies[REPLY_250_DIRCHANGE_SUCCESS]), 0);
				continue;
			}
			
			/* make sure dirToChange is a subdirectory of the current
			directory to prevent the user from jumping multiple directories
			with the dirToChangeTo string (this check especially important
			to the prevent the use of ".."s somewhere in the string which
			might allow the user to navigate above the root directory). */
			
			DIR *dp;
			struct dirent *ep;
			bool entryExistsInCurrentDir;
			dp = opendir(dir);
			if (dp != NULL)
			{
				while ( ep = readdir(dp) )
					if ( strcmp( ep->d_name, dirToChangeTo ) == 0)
						entryExistsInCurrentDir = true;
				closedir(dp);
			}
			else
				ExitError("For some reason the current directory doesn't exist, or opendir() failed for some other reason.");
			
			if ( entryExistsInCurrentDir == false )
			{
				send(controlSocket, replies[REPLY_550_DIRCHANGE_FAILURE], strlen(replies[REPLY_550_DIRCHANGE_FAILURE]), 0);
				continue;
			}
			
			/* Finally, we have to make sure the file entry we found
			is actually a directory, not a regular file. */
			sprintf(pathBuf, "%s%s%s", dir, dirToChangeTo, "/");
			int fileInfo = GetFileInfo( pathBuf );
			if ( fileInfo == FILEINFO_DIR )
			{
				strcpy( dir, pathBuf );
				send(controlSocket, replies[REPLY_250_DIRCHANGE_SUCCESS], strlen(replies[REPLY_250_DIRCHANGE_SUCCESS]), 0);
			}
			else
			{
				send(controlSocket, replies[REPLY_550_DIRCHANGE_FAILURE], strlen(replies[REPLY_550_DIRCHANGE_FAILURE]), 0);
			}
		}
		/* PASV command - Reply over the the control connection with
		the IP and port info of the data transfer connection listening
		IP and port, and then fork off the data transfer process (DTP)
		which will get a command from the control connection while
		listening for a connection from the user on the data transfer
		connection. Once the DTP gets the command over the control
		connectionit will do the specified command over the data
		connection once the user connects. */
		else if (strcmp(cmdTokens[0], ftpCmds[FTPCMD_PASV]) == 0)
		{
			printf("Receivied PASV command.\n");
			
			/* Create new listening socket */
			
			const int DTP_MAX_BACKLOG_CONNECTIONS = 1;
			const uint16_t RANDOM_DTP_LISTEN_PORT = 49064; // HACK: for our random listening port we're just going to make a port number up
			int dataTransferListenSocket = CreateListenSocket( DTP_MAX_BACKLOG_CONNECTIONS, RANDOM_DTP_LISTEN_PORT, false, true );
			
			/* Say Bert.CS.UIC.edu is 131.193.40.32 to the
			outside world. We want to get that address. */
			char localHostName[MAXHOSTNAMELEN];
			gethostname(localHostName, MAXHOSTNAMELEN);
			struct hostent* hostEntry = gethostbyname(localHostName);
			struct in_addr hostIPAddr = *(struct in_addr *)*hostEntry->h_addr_list;// TODO: make sure the first item in the list isn't 127.0.0.1 or something
			char* localIPString = inet_ntoa( hostIPAddr ); // points to the first entry in the list
			
			printf("PASV found IP: %s.\n", localIPString);
			
			/* Create the port string */
			
			unsigned char h1, h2, h3, h4;
			unsigned char p1, p2;
			
			// HACK HACK: this stuff is not endian safe
			unsigned char* bytePtr = (unsigned char*)&hostIPAddr;
			h1 = bytePtr[0];
			h2 = bytePtr[1];
			h3 = bytePtr[2];
			h4 = bytePtr[3];
			
			bytePtr = (unsigned char*)&RANDOM_DTP_LISTEN_PORT;
			p2 = bytePtr[0]; // high byte
			p1 = bytePtr[1]; // low byte
			
			// port = p1 * 256 + p2 
			char pasvPortString[30]; // (xxx,yyy,zzz,www,ppp,nnn)
			sprintf(pasvPortString, "(%i,%i,%i,%i,%i,%i)", h1, h2, h3, h4, p1, p2);
			
			printf("Port value test: p1*256+p2 ?= port :: %d ?= %d.\n", p1*256+p2, RANDOM_DTP_LISTEN_PORT);
			printf("PASV string: %s.\n", pasvPortString);
			
			/* Send the PASV reply */
			
			char pasvReply[200];
			sprintf(pasvReply, replies[REPLY_227_PASSIVE_MODE], pasvPortString);
			send(controlSocket, pasvReply, strlen(pasvReply), 0);
			
			int dtp_pid = fork();
			if ( !dtp_pid )
			{
				/* Data Transfer Process (DTP) code */
				printf("Created data transfer process.\n");
				
				/* Get the next command from the control connection (RETR, STOR, LIST) */
				ret = GetControlConnectionCmd(
					controlSocket,
					msgBuf, msgBufLen, MSG_BUF_MAX_SIZE,
					cmdTokens, numCmdTokens
				);
				if (ret == 1) // control socket was closed for some reason
				{
					close(dataTransferListenSocket);	// done with the listen socket
					exit(EXIT_FAILURE);
				}
				
				/* Accept the user connection */
				struct sockaddr_in remoteAddr;
				int dataTransferSessionSocket = AcceptConnectionFromListenSocket(dataTransferListenSocket, &remoteAddr);
				printf("Data transfer process (DTP) received connection from %s\n", inet_ntoa(remoteAddr.sin_addr));
				
				FTPDataTransferSession(controlSocket, dataTransferSessionSocket);
				
				close(dataTransferSessionSocket);	// when done with the session close the socket
				close(dataTransferListenSocket);	// close the listen socket too
				
				printf("Closing data transfer process.\n");
				exit(EXIT_SUCCESS);				// exit with success code
			}
			
			/* parent continues here */
			
			close(dataTransferListenSocket); // parent doesn't need the this socket
			
			/* wait for the child process to complete */
			waitpid( dtp_pid, NULL, 0 ); // TODO: check for things other than normal termination
			printf("Server-PI resuming execution.\n");
		}
		/* TYPE command */
		else if (strcmp(cmdTokens[0], ftpCmds[FTPCMD_TYPE]) == 0)
		{
			if ( strcmp(cmdTokens[1], "I") == 0 ) // binary
			{
				send(controlSocket, replies[REPLY_200_TYPE_SET_TO_I], strlen(replies[REPLY_200_TYPE_SET_TO_I]), 0);
			}
			else if ( strcmp(cmdTokens[1], "A") == 0 ) // ASCII
			{
				send(controlSocket, replies[REPLY_200_TYPE_SET_TO_A], strlen(replies[REPLY_200_TYPE_SET_TO_A]), 0);
			}
			else
			{
				// TODO: handle other stuff
			}
		}
		/* QUIT command */
		else if (strcmp(cmdTokens[0], ftpCmds[FTPCMD_QUIT]) == 0)
		{
			printf("Receivied QUIT command.\n");
			send(controlSocket, replies[REPLY_221_END_SESSION], strlen(replies[REPLY_221_END_SESSION]), 0);
			break; // break out of the loop
		}
		/* Unknown command */
		else
		{
			printf("Receivied unknown command.\n");
			send(controlSocket, replies[REPLY_500_UNKNOWN_COMMAND], strlen(replies[REPLY_500_UNKNOWN_COMMAND]), 0);
		}
	}
	
	/* Done */
	printf("Ended FTP session from %s\n", inet_ntoa(remoteAddr.sin_addr));
}

void FTPDataTransferSession(int controlSocket, int dataTransferSessionSocket)
{
	/* LIST command - Sends a list of files to be displayed. */
	if (strcmp(cmdTokens[0], ftpCmds[FTPCMD_LIST]) == 0)
	{
		printf("Receivied LIST command.\n");
		send(controlSocket, replies[REPLY_150_SENDING_DIR_LIST], strlen(replies[REPLY_150_SENDING_DIR_LIST]), 0);
		//FILE* lsOutput = popen("ls -l -n", "r");
		char cmdString[PATH_MAX+100]; // path plus room for the command
		sprintf(cmdString, "sh -c \"ls %s -l > .dirlist\"", dir);
		system(cmdString);
		FILE* dirListFile = fopen(".dirlist", "r"); // open in program's working directory
		
		char lineBuf[2000]; // HACK HACK: totally made up buffer size
		while ( fgets( lineBuf, 2000, dirListFile ) != NULL )
		{
			int lineBufLen = strlen( lineBuf );
			lineBuf[lineBufLen-1] = '\r';
			lineBuf[lineBufLen] = '\n';
			lineBufLen++;
			send(dataTransferSessionSocket, lineBuf, lineBufLen, 0);
		}
		fclose(dirListFile);
		
		send(controlSocket, replies[REPLY_226_DIR_SEND_OK], strlen(replies[REPLY_226_DIR_SEND_OK]), 0);
	}
	/* RETR command - Retrieve file over the data transfer connection. */
	else if (strcmp(cmdTokens[0], ftpCmds[FTPCMD_RETR]) == 0)
	{
		printf("Received RETR command.\n");
		
		sprintf(pathBuf, "%s%s", dir, cmdTokens[1]); // cmdTokens[1] is the file name
		FILE* fileToSend = fopen(pathBuf, "rb");
		if (fileToSend == NULL)
		{
			printf("RETR couldn't open file.\n");
			send(controlSocket, replies[REPLY_550_FILE_NOT_FOUND], strlen(replies[REPLY_550_FILE_NOT_FOUND]), 0);
			return; // error
		}
		
		//char fileSizeInBytes[20];
		char retrReply[PATH_MAX+1000]; // HACK : max path + max number of digits for byte size + reply string
		int fileSize = GetFileSize(pathBuf);
		sprintf(retrReply, replies[REPLY_150_OPEN_BINARY_DATA_CONNECTION], cmdTokens[1], fileSize);
		send(controlSocket, retrReply, strlen(retrReply), 0);
		
		/* FTP has three transfer modes: STREAM, BLOCK, and COMPRESSED.
		We will send using STERAM mode which simply sends a stream of
		bytes and treat all files as "file structures" as defined in
		RFC 959 as opposed to "record structures." From RFC959: "If the
		structure is a file structure, the EOF is indicated by the sending
		host closing the data connection and all bytes are data bytes."
		So, we just close the connection after sending all the bytes. */
		
		while ( 1 )
		{
			/* read blocks of 1024 bytes into msgBuf and then send */
			size_t numBytesRead = fread(msgBuf, 1, 1024, fileToSend);
			send(dataTransferSessionSocket, msgBuf, numBytesRead, 0);
			if (numBytesRead < 1024) // reached end of file
				break;
		}
		
		fclose(fileToSend);
		
		send(controlSocket, replies[REPLY_226_FILE_SEND_OK], strlen(replies[REPLY_226_FILE_SEND_OK]), 0);
	}
	/* STOR command - Receive file from user. */
	else if (strcmp(cmdTokens[0], ftpCmds[FTPCMD_STOR]) == 0)
	{
		printf("Received STOR command.\n");
		
		char* newFileName = cmdTokens[1];
		sprintf(pathBuf, "%s%s", dir, newFileName);
		FILE* fileToReceive = fopen(pathBuf, "wb");
		if (fileToReceive == NULL)
		{
			printf("STOR couldn't create file.\n");
			send(controlSocket, replies[REPLY_550_COULDNT_OPEN_FILE], strlen(replies[REPLY_550_COULDNT_OPEN_FILE]), 0);
			return; // error
		}
		
		send(controlSocket, replies[REPLY_150_READY_FOR_TRANSFER], strlen(replies[REPLY_150_READY_FOR_TRANSFER]), 0);
		
		/* keep reading until the connection is closed */
		while (1)
		{
			if ( ( msgBufLen = recv( dataTransferSessionSocket, msgBuf, MSG_BUF_MAX_SIZE, 0 ) ) == -1 )
				ExitError("Error receiving control connection data.");
			if ( msgBufLen == 0 ) // recv() returns 0 if the remote side has closed the connection */
				break;
			fwrite( msgBuf, 1, msgBufLen, fileToReceive );
		}
		
		send(controlSocket, replies[REPLY_226_RECEIVED_FILE_CLOSING_CONNECTION], strlen(replies[REPLY_226_RECEIVED_FILE_CLOSING_CONNECTION]), 0);
	}
	/* Unknown or invalid command */
	else
	{
		printf("Received invalid DTP command.\n");
		send(controlSocket, replies[REPLY_500_UNKNOWN_COMMAND], strlen(replies[REPLY_500_UNKNOWN_COMMAND]), 0);
		return; // error
	}
}

void PrintHelp()
{
	printf("\nftpserver [port [directory]]\n\n");
	printf("Default port is 21.\n");
	printf("Default directory is the current directory.\n\n");
}

void ParseCmdLineArgs(int argc, char* argv[], char*& dir, int& listenPort)
{
	/* parse the command line argv[0] is the name of binary so an
	argc of 1 means 0 arguments */
	if (argc == 1)			// no arguments
	{
		listenPort = FTP_DEFAULT_SERVER_PORT;	// use the default FTP port (needs superuser rights for listening on port 21)
		dir = "./";				// use the current directory
	}
	else if (argc == 2)		// one arguement
	{
		if ( strcmp(argv[1], "-h") || strcmp(argv[1], "-help") )
		{
			PrintHelp(); // print help message
			exit(1);
		}
		listenPort = atoi( argv[1] );	// use the port from the command line
		dir = "./";		// use the default directory
	}
	else if (argc == 3)		// two arguments
	{
		listenPort = atoi( argv[1] );	// use the port from the command line
		dir = argv[2];		// use the directory from the command line
	}
	else 				// something unexpected
	{
		printf("Unexpected number of command line arguments.\n\n");
		PrintHelp();
		exit(EXIT_FAILURE);
	}
	
	// TODO: check if the directory exists
	// also apply a slash to the end of the name if it does have one
}

void SigChildHandler(int s)
{
	while(waitpid(-1, NULL, WNOHANG) > 0)
		;
}

int main(int argc, char* argv[])
{
	/* Parse the command line arguments */
	int listenPort = -1;		// port to listen on
	char* dir = NULL;		// directory to serve
	ParseCmdLineArgs(argc, argv, dir, listenPort);
	printf("Running server in directory %s, and on port %i.\n", dir, listenPort);
	
	/* Create the listening socket for our FTP server */
	int listenSocket = CreateListenSocket( FTP_MAX_BACKLOG_CONNECTIONS, listenPort, false, true );

	/* Do this to reap zombie child processes */
	struct sigaction sa;			// need this struct for handling signals and destroying zombie child procs
	sa.sa_handler = SigChildHandler;	// function pointer
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if ( sigaction(SIGCHLD, &sa, NULL) == -1 )
		ExitError("sigaction() failed.");
	
	while (1)
	{
		/* Accept the next connection on the backlog queue. Blocks if
		there are no connections in the queue. */
		struct sockaddr_in remoteAddr;
		int acceptSocket = AcceptConnectionFromListenSocket(listenSocket, &remoteAddr);
		printf("FTP server received connection from %s\n", inet_ntoa(remoteAddr.sin_addr));
		
		/* Each FTP session gets its own process. */
		if ( !fork() )			
		{
			// child process code
			close(listenSocket);				// child doesn't need listen socket
			FTPSession(acceptSocket, dir, remoteAddr);	// begin the FTP session
			close(acceptSocket);				// when done with the session close the socket
			exit(EXIT_SUCCESS);				// exit with success code 0
		}
		
		// parent process continues here
		close(acceptSocket);			// parent doesn't need the accept socket anymore
	}
	
	return 0;
}

