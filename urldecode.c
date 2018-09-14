/*
 * urldecode.c
 *
 *  Created on: Nov 27, 2010
 *      Author: vsam
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include "urldecode.h"



static char* urldecode(const char* s, int isform)
{
	char* ret;
	char* pos;
	char enc;
	char encbuf[3];

	ret = malloc((strlen(s)+1)*sizeof(char));

	pos = ret;
	while((enc = *s++)) {
		if(enc=='+' && isform) {
			*pos++ = ' ';
		} else if(enc=='%') {
			/* Check sanity */
			if( (!isxdigit(s[0])) || (!isxdigit(s[1])) )
				break;
			sprintf(encbuf, "%c%c", s[0], s[1]);
			*pos ++ = (char) strtol(encbuf,NULL,16);
			s += 2;
		}
		else {
			*pos ++ = enc;
		}
	}

	*pos = '\0';
	return ret;
}

char* www_urldecode(const char* s) { return urldecode(s,0); }

char* www_form_urldecode(const char* s) { return urldecode(s,1); }

