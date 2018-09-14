/*
 * linkedlist.h
 *
 *  Created on: Oct 29, 2010
 *      Author: vsam
 */

#ifndef LINKEDLIST_H_
#define LINKEDLIST_H_

#include <stddef.h>

/*
 * An implementation of a  linked list of pointers.
 *
 * This is a classic doubly-linked list with keys being of type "void *",
 * and a full set of list operations.
 * 
 * A list stores a sequence of pointers. Each pointer is stored in a structure
 * of type ListNode
 */



/*
  ListNode is a pointer type which points to a position (a node, or the end of the list)
  in a linked list.
 */
typedef struct List_node_t {
	struct List_node_t 
	  *prev, *next; 	/* Previous and next nodes. */
	void* data;  		/* The data of this node. */
} *ListNode;


/*
  The main type.

  Every new List variable MUST be initialized by calling List_init.
  
  Before a list can be deleted, it must be empty (else, there will be a memory leak).
  To empty the list, use List_clear.

  Positions
  ---------

  Assume list L has N keys,  x(0) x(1) ... x(N-1).
  
  Then, L has N+1 valid positions (ListNode values), p(0), p(1), p(2), ... p(N-1) p(N).

  Positions p(0) to p(N-1) are called nodes, and contain data:
  For each 0<= i < N,  x(i) == p(i)->data  (the data field of the ListNode).
  ListNodes have two other fields: prev and next.
  For each i, p(i)->next == p(i+1), and p(i+1)->prev == p(i). 

  Position p(N) is the end of L and **it is not a node**. We denote it by end(L).
  end(L) = p(N) == p(N-1)->next == p(0)->prev  
  Each List object has a different end node: end(L1) != end(L2) 

  Assume that a list L is not empty.
  By begin(L) we denote p(0) (the head node of the list)
  and by rbegin(L) we denote p(N-1) (the tail node of the list)

  For an empty list L, begin(L) == end(L) == rbegin(L)

  The field  end(L)->data is undefined and unused by the List operations.

  Ranges
  -------

  A range of size n is a (possibly empty) sequence of n>=0 adjacent positions, 

  p(i) p(i+1) ... p(i+n-1)

  We denote a range by [ p(i) , p(i+n) ) as a left-closed, right-open "interval".
  
  Examples:
  [p,p) is a range of size 0

  [ begin(L), end(L) )  is the range of all positions corresponding to keys.

  We can iterate over positions of a range [p,q) with the well-known idiom:


  ListNode x;
  for(x = p;  x != q; x=x->next) 
  {
    ...
  }


  Splicing
  ----------

  Splicing is an operation which allows us to MOVE (not copy!) sublists into
  different positions.

  Let i be a position in list L1, then we can split the nodes in L1 into
  two parts:
  
  [begin(L1), i) [i, end(L1))

  Now, assume that we have a range [p, q) from list L2, so that the nodes of
  L2 are written in 3 parts:

  [begin(L2), p) [p,q) [q, end(L2))

  Operation splice(i, p, q) will move the nodes [p,q) from L2 to L1, so that,
  after the operation, we have

  L1 ::=   [begin(L1), i) [p,q) [i, end(L1))
  and
  L2 ::=   [begin(L2), p) [q, end(L2))

  Note that this operation takes time O(1).


  Uses of splicing
  -----------------

  Splicing is the main way to manipulate lists in algorithms.
  Some examples:


  1) to swap two lists L1 and L2, we can do the following:

  p = begin(L1);
  splice(p, begin(L2), end(L2));
  splice(end(L2), p, end(L1));


  2) To "rotate right" a list L we can do

  splice(begin(L), rbegin(L), end(L))

    To "rotate left",

  splice(begin(L), begin(L)->next, end(L))


  3) To concatenate two lists, L1 and L2:

  splice(end(L1), begin(L2), end(L2))


  4) To reverse the nodes in range [p.q)

  while(q->prev != p)
    splice(p, q->prev, q);
  


  Operations
  ------------

  Access to list positions:

  List_begin         The head position, or end if the list is empty.
  List_rbegin        The tail position, or end if the list is empty.
  List_end           The end of the list

  Inserting elements:

  List_insert_before insert a key before a position
  List_insert_after  insert a key after a position
  List_push_front    insert a key before begin(L) (the new head)
  List_push_back     insert a key before end(L) (the new tail)

  Removing elements:
  
  List_clear         remove all nodes from list, leaving it empty
  List_remove        remove a node, returning its key
  List_pop_front     remove the head, returning its key
  List_pop_back      remove the tail, returning its key

  Access to keys:

  List_front         the key of the head
  List_back          the key of the tail
  List_at            the key at the i-th position

  List splicing:

  List_splice        splice a range
  List_spliceOne     splice one node
  List_spliceAll     splice all nodes
  
 */
typedef struct List {
	struct List_node_t node;
} List;



/*
 * Operations for lists.
 *
 * In the following, we use the concept of range [p, q).
 * 
 * A range is a sequence of ListNodes
 *
 */


/* Return the beginning of list */
extern ListNode List_begin(List* list);

/* Return the reverse beginning of list */
extern ListNode List_rbegin(List* list);

/* Return the end of list*/
extern ListNode List_end(List* list);

/* Return 1 is list is empty, else 0 */
extern int List_empty(List* list);

/* Return the size of the list */ 
extern size_t List_size(List* list);

/*
  Initialize a list. This function MUST be called for every newly created list.
 */
extern void List_init(List* list);

/*
  Remove all nodes from the list.
 */
extern void List_clear(List* list);


/* Insert a new node with the given data, just before insertpos */
extern ListNode List_insert_before(ListNode insertpos, void* data);

/* Insert a new node with the given data, just after insertpos. 
   This is equivalent to 
   List_insert_before(insertpos->next, data)
*/
extern ListNode List_insert_after(ListNode insertpos, void* data);

/* Remove node from the list, returning the removed node's data. */
extern void* List_remove(ListNode node);


/* Prepend a key to the list. This is eqivalent to
   List_insert_before( List_begin(list), data )
*/
extern ListNode List_push_front(List* list, void* data);

/* Append a key to the list. This is eqivalent to
   List_insert_before( List_end(list), data )
 */
extern ListNode List_push_back(List* list, void* data);

/* Pop a key from the front of the list. The list must be non-empty.
   This is equivalent to
   List_remove( List_begin(list) )
 */
extern void* List_pop_front(List* list);

/* Pop a key from the back of the list. The list must be non-empty 
   This is equivalent to
   List_remove( List_rbegin(list) )
*/
extern void* List_pop_back(List* list);

/* Return the key of the front of the list. The list must be non-empty.
   This is equivalent to
   List_begin(list)->data
*/
extern void* List_front(List* list);

/* Return the key of the back of the list. The list must be non-empty.
   This is equivalent to 
   List_rbegin(list)->data
*/
extern void* List_back(List* list);

/* Return the n-th element of the list. The list size must be at least n+1. */
extern void* List_at(List* list, size_t n);


/*
  Remove the range [from,to) and insert it before insertpos.

  If any of from, to, or insertpos are equal, the operation has no effect.
  insertpos MUST NOT belong in the range [from, to)

  This operation is similar to the following recursion:
  
  function splice(insertpos, from, to):
    if from->next != to:
       pos = splice(insertpos, from->next, to)
    else:
       pos = insertpos
    data = remove(from)
    return insert_before(pos, data)
  

  However, List_splice takes O(1) time.
 */
extern void List_splice(ListNode insertpos,  ListNode from, ListNode to);


/*
  Equivalent to 
  List_splice(insertpos, List_begin(L), List_end(L))
 */
extern void List_spliceAll(ListNode insertpos,  List* L);

/*
  Equivalent to
  List_splice(insertpos, node, node->next)
 */
extern void List_spliceOne(ListNode insertpos,  ListNode node);



/**************************
   Algorithms for lists
   ************************/

/*
  Copy range [from, to) and insert it before dest.
 */
extern void List_copy(ListNode from, ListNode to, ListNode dest);


/*
  Sort the elements of the list, using the given comparison lessPred.

  lessPred(a,b) returns 1 if a points to an element STRICTLY LESS than b, else
  it returns zero.

  Note: two elements are considered equal if lessPred(a,b)==lessPred(b,a)==0

  Sorting takes time O(n*log(n)) and does not consume any memory.
 */
extern void List_sort(List* list, int (*lessPred)(void*, void*)); 


/*
  Use this macro to shorten the frequent case of iterating over the whole list.
  Example:


  List* L;
  ListNode p;

  ...

  List_foreach(p, L) {
    ...
  }

 */
#define List_foreach(var, list) \
		for(var = List_begin(list); var != List_end(list); var = var->next)


#endif /* LINKEDLIST_H_ */
