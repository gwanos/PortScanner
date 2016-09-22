#include <stdio.h>
#include <stdlib.h>

#include "HandleError.h"

void DisplayErrorMessage(char *message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}