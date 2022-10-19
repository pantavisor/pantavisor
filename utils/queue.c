#include "queue.h"
#include "list.h"

#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

struct pv_queue_entry {
	char *data;
	int size;
	struct dl_list list;
};

struct pv_queue {
	// size in bytes
	int cap;
	int size;
	char *mem;
	char *fname;
	bool disk;
	struct dl_list entries;
};

static struct pv_queue *queue_new(int capacity)
{
	struct pv_queue *q = calloc(1, sizeof(struct pv_queue));
	if (!q)
		return NULL;
	q->size = 0;
	q->cap = capacity;
	dl_list_init(&q->entries);

	return q;
}

struct pv_queue *pv_queue_new_from_mem(int capacity)
{
	struct pv_queue *q = queue_new(capacity);
	if (!q)
		return NULL;

	q->fname = NULL;
	q->disk = false;
	q->mem = calloc(capacity, sizeof(char));
	if (!q->mem) {
		pv_queue_free(q);
		return NULL;
	}

	return q;
}
struct pv_queue *pv_queue_new_from_disk(int capacity, const char *fname)
{
	struct pv_queue *q = queue_new(capacity);
	if (!q)
		return NULL;

	q->disk = true;
	q->fname = strdup(fname);
	int fd = open(fname, O_CREAT | O_TRUNC | O_RDWR, 0644);
	if (fd < 0) {
		pv_queue_free(q);
		return NULL;
	}
	ftruncate(fd, capacity);

	q->mem = mmap(NULL, q->cap, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);

	if (q->mem == MAP_FAILED) {
		pv_queue_free(q);
		return NULL;
	}

	return q;
}

void pv_queue_free(struct pv_queue *q)
{
	if (!q)
		return;

	struct pv_queue_entry *it, *tmp;
	dl_list_for_each_safe(it, tmp, &q->entries, struct pv_queue_entry, list)
	{
		dl_list_del(&it->list);
		free(it);
	}

	if (q->mem) {
		if (!q->disk) {
			free(q->mem);
		} else {
			if (q->mem != MAP_FAILED)
				munmap(q->mem, q->size);
			unlink(q->fname);
		}
	}
	free(q);
}

int pv_queue_size(const struct pv_queue *q)
{
	return q ? q->size : -1;
}

int pv_queue_capacity(const struct pv_queue *q)
{
	return q ? q->cap : -1;
}

static void queue_mem_move(struct pv_queue *q, int size)
{
	q->size -= size;
	memmove(q->mem, q->mem + size, q->cap - size);

	struct pv_queue_entry *it, *tmp;
	int diff = size;
	dl_list_for_each_safe(it, tmp, &q->entries, struct pv_queue_entry, list)
	{
		it->data -= diff;
		diff = it->size;
	}
}

static void queue_drop_entries(struct pv_queue *q, int size)
{
	struct pv_queue_entry *entry = NULL;
	while ((q->cap - q->size) < size) {
		entry = dl_list_last(&q->entries, struct pv_queue_entry, list);
		if (!entry)
			return;
		dl_list_del(&entry->list);
		queue_mem_move(q, entry->size);
		free(entry);
	}
}

void pv_queue_push(struct pv_queue *q, char *data, int size)
{
	// if the queue does not have enough space
	// we need to drop the oldest entries
	if ((q->cap - q->size) < size)
		queue_drop_entries(q, size);

	struct pv_queue_entry *entry = calloc(1, sizeof(struct pv_queue_entry));
	dl_list_init(&entry->list);
	dl_list_add(&q->entries, &entry->list);
	entry->data = q->mem + q->size;
	q->size += size;
	memcpy(entry->data, data, size);
	entry->size = size;
}

char *pv_queue_pop(struct pv_queue *q, int *size)
{
	struct pv_queue_entry *entry =
		dl_list_last(&q->entries, struct pv_queue_entry, list);

	if (!entry)
		return NULL;

	char *data = calloc(entry->size, sizeof(char));
	memcpy(data, entry->data, entry->size);
	if (size)
		*size = entry->size;

	dl_list_del(&entry->list);
	queue_mem_move(q, entry->size);
	free(entry);

	return data;
}

bool pv_queue_has_space(struct pv_queue *q, int size)
{
	return (q->cap - q->size) >= size;
}
