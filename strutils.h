/*
 * Author: vsam
 */
#ifndef STRUTILS_H
#define STRUTILS_H

#include "linkedlist.h"


/*
  Return a pointer to the '\0' terminating the string.
 */
extern const char* strend(const char*);


/*
  Return a copy of the range of chars [from, to)
 */
extern char* strrange(const char* from, const char* to);


/*
  Return a copy of str with leading whitespace removed.
  Whitespace is defined as anything recognized by function isspace. 
 */
extern char* strltrim(const char* s);


/*
  Return a copy of str with trailing whitespace removed.
  Whitespace is defined as anything recognized by function isspace. 
*/
extern char* strrtrim(const char* s);


/*
  Return a copy of str with leading and trailing whitespace removed.
  Whitespace is defined as anything recognized by function isspace. 
 */
extern char* strtrim(const char* str);


/*
  Split the input string in places matching string sep and append
  the pieces to the end of strlist. Return the number of pieces found.
  If sep is not found in input, input is appended to strlist and 1 is
  returned.

  If the separator is empty, 0 is returned.
*/
extern int strsplit(const char* input, const char* sep, List* strlist);


/*
  Join the strings in the given ListNode range [from,to) , 
  separated by sep.
 */
extern char* strjoin(const char* sep, ListNode from, ListNode to);


/*
  Concatenate the arguments of the function. The last argument must
  be null.
  e.g.  strconcat("Hello"," ","world!",NULL)
  returns a malloc'd concatenated strin "Hello world!".

*/
extern char* strconcat(const char*,...);


/* Return 1 if s1 is strictly less alphabetically than s2, else return 0 */
int strless(const char* s1, const char* s2);

/* Return 1 if s1 is equal to s2, else return 0 */
int streq(const char* s1, const char* s2);




#endif
