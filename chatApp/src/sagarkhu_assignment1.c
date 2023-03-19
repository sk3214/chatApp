#include <stdio.h>
#include <stdlib.h>

#include "../include/global.h"
#include "../include/logger.h"

#include "server.h"
#include "client.h"

/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list
 * @return 0 EXIT_SUCCESS
 */
int main(int argc, char **argv)
{
	/*Init. Logger*/
	cse4589_init_log(argv[2]);

	/*Clear LOGFILE*/
	fclose(fopen(LOGFILE, "w"));

	/*Start Here*/
	int port = atoi(argv[2]);
	if(strcmp(argv[1],"s")==0)
		start_server(port);
	else if(strcmp(argv[1],"c")==0)
		start_client(port);

	return 0;
}
