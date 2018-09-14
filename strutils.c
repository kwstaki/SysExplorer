
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "strutils.h"

const char* strend(const char* s)
{
	while(*s) s++;
	return s;
}

char* strrange(const char* from, const char* to)
{
	char* ret = (char*)malloc((to-from)+1);
	char *p=ret;
	while(from!=to) {
		*p = *from;
		p++; from++;
	}
	*p = '\0';
	return ret;
}


char* strltrim(const char* s)
{
	while(isspace(*s)) ++s;
	return strdup(s);
}

char* strrtrim(const char* s)
{
	int n;
	char *p;

	/* Null string */
	if(*s == '\0') return strdup(s);

	/* Find the length of the string */
	n = strlen(s);
  
	while(n>0) {
		if(isspace(s[n-1]))
			n--;
		else
			break;
	}
	
	/* Make the copy */
	p = (char*) malloc(n+1);
	memcpy(p,s,n);
	p[n] = '\0';
	return p;
}


char* strtrim(const char* s)
{
	/* move s down the string to trim left */
	while( (*s != '\0') && isspace(*s) ) s++;
	/* use rtrim */
	return strrtrim(s);
}


int strsplit(const char* input, const char* sep, List* strlist)
{
	int frags,seplen;
	frags = 0;
	seplen  = strlen(sep);

	if(seplen==0) return 0;

	while(1) {
		char *spos = strstr(input,sep);
		frags++;
		if(spos==NULL) {
			List_push_back(strlist, strdup(input));
			break;
		} else {
			List_push_back(strlist, strrange(input, spos));
			input = spos+seplen;
		}
	}
		
	return frags;
}

static char* bufappend(char* dest, const char* src)
{
	while(*src != '\0') {
		*(dest++) = *(src++);
	}
	*dest = '\0';
	return dest;
}

char* strjoin(const char* sep, ListNode from, ListNode to)
{
	size_t seplen, totlen;
	char *ret;
	ListNode p;
	size_t sl;
	char *pos;
	const char *csep;

	seplen = strlen(sep);

	/* First compute size of result */
	totlen = 0;
	sl = 0;
	for(p=from; p!=to; p=p->next) {
		totlen += sl; 
		sl = seplen;
		if(p->data != NULL) 
			totlen += strlen((const char*) p->data);
	}
	
	
	ret = (char*) malloc(totlen+1);
	
	/* Create the output */
	pos = ret;
	csep = "";
	for(p=from; p!=to; p=p->next) {
		pos = bufappend(pos,csep);
		csep = sep;

		if(p->data!=NULL)
			pos = bufappend(pos,(const char*) p->data);
	}
	return ret;
}


char* strconcat(const char* first, ...)
{
	List L;
	va_list ap;
	char* p;

	List_init(&L);
	List_push_back(&L, (char*)first);

	va_start(ap, first);
	while(1) {
		p = va_arg(ap, char*);
		if(p==NULL) break;		
		List_push_back(&L, p);
	}
	
	p = strjoin("", List_begin(&L), List_end(&L));
	List_clear(&L);
	return p;
}

#include <stdio.h>

int strless(const char* s1, const char* s2)
{
	return strcmp(s1,s2)<0;
}


int streq(const char* s1, const char* s2)
{
	return strcmp(s1,s2)==0;
}
