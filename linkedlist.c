/*
 * linkedlist.c
 *
 *  Created on: Oct 29, 2010
 *      Author: vsam
 */

#include <stdlib.h>
#include "linkedlist.h"


/*
 * List implementation
 */


ListNode List_begin(List* list)
{
	return list->node.next;
}

ListNode List_rbegin(List* list)
{
	return list->node.prev;
}

ListNode List_end(List* list)
{
	return & list->node;
}

void List_init(List* list)
{
	list->node.next = list->node.prev = List_end(list);
}

int List_empty(List* list)
{
	return List_begin(list)== List_end(list);
}

size_t List_size(List* list)
{
	unsigned int count=0;
	ListNode node;
	List_foreach(node, list) { ++count; }
	return count;
}

void List_clear(List* list)
{
	while(! List_empty(list))
		List_pop_front(list);
}


static void insert_before(ListNode pos, ListNode node)
{
	node->next = pos;
	node->prev = pos->prev;
	pos->prev->next = node;
	pos->prev = node;
}

static void remove_node(ListNode node)
{
	node->prev->next = node->next;
	node->next->prev = node->prev;
}


void* List_front(List* list) {
	return List_begin(list)->data;
}

void* List_back(List* list)
{
	return List_rbegin(list)->data;
}

void* List_at(List* list, size_t n)
{
	ListNode l = List_begin(list);
	while( (n--)>0 ) l = l->next;
	return l->data;
}


ListNode List_insert_before(ListNode insertpos, void* data)
{
	ListNode node = (struct List_node_t*)malloc(sizeof(struct List_node_t));
	node->data = data;
	insert_before(insertpos,node);
	return node;
}

ListNode List_insert_after(ListNode insertpos, void* data)
{
	return List_insert_before(insertpos->next, data);
}

void* List_remove(ListNode node)
{
	void* data = node->data;
	remove_node(node);
	free(node);
	return data;
}

ListNode List_push_front(List* list, void* data)
{
	return List_insert_before(List_begin(list),data);
}

ListNode List_push_back(List* list, void* data)
{
	return List_insert_before(List_end(list),data);
}

void* List_pop_back(List* list)
{
	return List_remove(List_rbegin(list));
}

void* List_pop_front(List* list)
{
	return List_remove(List_begin(list));
}


void List_splice(ListNode insertpos,  ListNode from, ListNode to)
{
	ListNode t1, f1, i1;

	if(from==to || from==insertpos || to==insertpos) return;

	i1 = insertpos->prev;
	f1 = from->prev;
	t1 = to->prev;

	from->prev = i1;
	i1->next = from;

	insertpos->prev = t1;
	t1->next = insertpos;

	to->prev = f1;
	f1->next = to;	
}

void List_spliceAll(ListNode insertpos,  List* L)
{
	List_splice(insertpos, List_begin(L), List_end(L));
}

void List_spliceOne(ListNode insertpos,  ListNode node)
{
	List_splice(insertpos, node, node->next);
}

void List_copy(ListNode from, ListNode to, ListNode dest)
{
	ListNode p;

	for(p=from; p!=to; p=p->next) {
		dest = List_insert_before(dest, p->data)->next;
	}
}


void List_sort(List* list,  int (*lessPred)(void*, void*) )
{
	List L[2];
	int turn;
	

	if(List_empty(list)) return; /* empty list is sorted */
	if(List_begin(list)==List_rbegin(list)) return; /* unary list is sorted */
	
	/* Split into two pieces */
	List_init(& L[0]);
	List_init(& L[1]);

	turn = 0;
	while(! List_empty(list)) {
		List_spliceOne(List_end(&L[turn]), List_begin(list));
		turn = 1-turn;
	}

	/* sort recursively */
	List_sort(& L[0],lessPred);
	List_sort(& L[1],lessPred);

	/* Merge to list */
	turn = 1;
	while(turn) {
		if(List_empty(& L[0]) || List_empty(& L[1])) {
			List_spliceAll( List_end(list), &L[0] );
			List_spliceAll( List_end(list), &L[1] );
			turn=0;

		} else {
			if(lessPred(List_front(&L[0]), List_front(&L[1])))
				List_spliceOne( List_end(list), List_begin(&L[0]) );
			else
				List_spliceOne( List_end(list), List_begin(&L[1]) );
		}

	}

}
