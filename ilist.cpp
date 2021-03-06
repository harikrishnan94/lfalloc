//
//  ilist.c
//  lfalloc
//
//  Created by hari on 09/07/17.
//  Copyright © 2017 hari. All rights reserved.
//

#include <cassert>

#include "ilist.h"

/*
 * Delete 'node' from list.
 *
 * It is not allowed to delete a 'node' which is not in the list 'head'
 *
 * Caution: this is O(n); consider using slist_delete_current() instead.
 */
void
slist_delete(slist_head *head, slist_node *node)
{
	slist_node *last = &head->head;
	slist_node *cur;
	bool found = false;

	while ((cur = last->next) != NULL)
	{
		if (cur == node)
		{
			last->next = cur->next;
			found = true;
			break;
		}
		last = cur;
	}
	Assert(found);

	slist_check(head);
}

#ifdef ILIST_DEBUG
/*
 * Verify integrity of a doubly linked list
 */
void
dlist_check(dlist_head *head)
{
	dlist_node *cur;

	if (head == NULL)
		elog(ERROR, "doubly linked list head address is NULL");

	if (head->head.next == NULL && head->head.prev == NULL)
		return;					/* OK, initialized as zeroes */

	/* iterate in forward direction */
	for (cur = head->head.next; cur != &head->head; cur = cur->next)
	{
		if (cur == NULL ||
			cur->next == NULL ||
			cur->prev == NULL ||
			cur->prev->next != cur ||
			cur->next->prev != cur)
			elog(ERROR, "doubly linked list is corrupted");
	}

	/* iterate in backward direction */
	for (cur = head->head.prev; cur != &head->head; cur = cur->prev)
	{
		if (cur == NULL ||
			cur->next == NULL ||
			cur->prev == NULL ||
			cur->prev->next != cur ||
			cur->next->prev != cur)
			elog(ERROR, "doubly linked list is corrupted");
	}
}

/*
 * Verify integrity of a singly linked list
 */
void
slist_check(slist_head *head)
{
	slist_node *cur;

	if (head == NULL)
		elog(ERROR, "singly linked list head address is NULL");

	/*
	 * there isn't much we can test in a singly linked list except that it
	 * actually ends sometime, i.e. hasn't introduced a cycle or similar
	 */
	for (cur = head->head.next; cur != NULL; cur = cur->next)
		;
}

#endif   /* ILIST_DEBUG */

