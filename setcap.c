/* This is automatically generated source, do not modify. Compile with gcc setcap.c -o setcap.

To list capabilities, try:

# setcap -l /bin/ping

To set program for running non-root but only few capabilities raised, use something like

# setcap -c NET_RAW -sd /bin/ping

 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>

#include "/usr/src/linux/include/linux/capability.h"
#include "/usr/src/linux/include/linux/elf.h"

#define NO_NHDR
/*
 * Definitions for generic ELF note handling code
 *
 * This software is being released under the GNU Public Licence.
 *
 * Copyright 1999, Jeremy Fitzhardinge <jeremy@goop.org>
 */

#ifndef NOTES_H
#define NOTES_H

/* An in-core note */
struct note {
	struct note *next;
	char *name;
	int type;
	int datasz;
	void *data;
};

int notesize(struct note *note);
int notefmt(struct note *, char *, int);
struct note *noteparse(const char *, int, struct note *);

#ifndef NO_NHDR
typedef struct {
	Elf32_Word	n_namesz;	/* Name size */
	Elf32_Word	n_descsz;	/* Content size */
	Elf32_Word	n_type;		/* Content type */
} Elf32_Nhdr;
#endif
#endif
/*
 * Some common ELF note handling routines
 *
 * This software is being released under the GNU Public Licence.
 *
 * Copyright 1999, Jeremy Fitzhardinge <jeremy@goop.org>
 */

#define roundup(x, y)  ((((x)+((y)-1))/(y))*(y))

/* Calculate the size of a set of notes in an ELF file */
int notesize(struct note *note)
{
	int sz = 0;

	for(; note != NULL; note = note->next)
	{
		sz += sizeof(Elf32_Nhdr);
		sz += roundup(strlen(note->name), 4);
		sz += roundup(note->datasz, 4);
	}

	return sz;
}

/* Generate a formatted note segment for an ELF file */
int notefmt(struct note *note, char *buf, int bufsz)
{
	int sz = notesize(note);
	char *cp;

	if (sz == 0 || bufsz < sz)
		return 0;

	cp = buf;

	for(; note != NULL; cp += notesize(note), note = note->next)
	{
		Elf32_Nhdr *hdr = (Elf32_Nhdr *)cp;
		hdr->n_namesz = strlen(note->name);
		hdr->n_descsz = note->datasz;
		hdr->n_type = note->type;
		memcpy(cp + sizeof(*hdr), note->name, strlen(note->name));
		memcpy(cp + sizeof(*hdr) + roundup(hdr->n_namesz, 4),
		       note->data, note->datasz);
	}

	return cp - buf;
}

/* Parse a note segment */
struct note *noteparse(const char *buf, int buflen, struct note *notes)
{
	while(buflen > sizeof(Elf32_Nhdr)) {
		Elf32_Nhdr *nhdr = (Elf32_Nhdr *)buf;
		struct note *note;
		char *cp;
		int sz;
		
		sz = sizeof(Elf32_Nhdr) + 
			roundup(nhdr->n_namesz, 4) + 
			roundup(nhdr->n_descsz, 4);
		if (buflen < sz)
			break;

		note = malloc(sizeof(*note));
		note->next = notes;
		notes = note;

		note->type = nhdr->n_type;

		note->name = cp = malloc(nhdr->n_namesz + 1);
		memcpy(cp, buf + sizeof(*nhdr), nhdr->n_namesz);
		cp[nhdr->n_namesz] = 0;

		note->datasz = nhdr->n_descsz;
		note->data = malloc(nhdr->n_descsz);
		memcpy(note->data, 
		       buf + sizeof(*nhdr) + roundup(nhdr->n_namesz, 4), 
		       nhdr->n_descsz);

		buf += sz;
		buflen -= sz;
	}

	if (buflen != 0)
		printf("noteparse: %d bytes left over\n", buflen);
	
	return notes;
}
/*                               (hey, emacs, this is -*- linux-c -*- mode)
 * Add a PT_NOTE segment to an ELF executable
 *
 * This is pretty generic at the moment, but its intended to be the core of
 * a capability-insertion utility.
 *
 * This software is being released under the GNU Public Licence.
 *
 * Copyright 1999, Jeremy Fitzhardinge <jeremy@goop.org>
 * Copyright 1999, Pavel Machek <pavel@ucw.cz> (I've nothing against LGPL :-)
 *

To list capabilities, try:

# addnote -l /bin/ping

To set program for running non-root but only few capabilities raised, use something like

# addnote -c NET_RAW -sd /bin/ping

 */



#define NO_NHDR

#ifdef DEBUG
#define DBG(x)	x
#else
#define DBG(x)
#endif

#define ELF_PAGESIZE	4096

/*
 * Notes have names and types.  All capabilities notes would have the same name ("CAPS"),
 * with different types to descriminate between different structures.  This could be used
 * for version control or for different levels of capabilities support.
 */
#define CAPNAME	"CAPS"
#define CT_CAPS	1		/* generic... */

/* Placeholder capability structure */
struct caps {
	int add;
	int drop;
	int require;
};

/* Segments in the ELF file */
struct segment {
	struct segment *next;
	int idx, origidx;

	Elf32_Phdr ph;
};

static struct segment *seg_insert(struct segment *list, const Elf32_Phdr *ph, int idx)
{
	struct segment *seg;
	struct segment **prev;
	struct segment *newseg;
	int lastidx = -1;

	for(prev = &list, seg = list;
	    seg != NULL; 
	    prev = &seg->next, seg = seg->next) {
		if (ph->p_offset <= seg->ph.p_offset)
			break;
	}

	newseg = malloc(sizeof(*newseg));

	newseg->next = seg;
	newseg->ph = *ph;
	*prev = newseg;

	if (idx == -1) {
		lastidx = 0;
		for(seg = list; seg != NULL; seg = seg->next)
			seg->idx = lastidx++;
	}

	return list;
}

static struct segment *seg_delete(struct segment *list, int idx)
{
	struct segment *seg, **prev;

	for(prev = &list, seg = list;
	    seg != NULL;
	    prev = &seg->next, seg = seg->next)
		if (seg->idx == idx) {
			*prev = seg->next;
			free(seg);
			break;
		}

	return list;
}

static off_t seg_freespace(struct segment *list, off_t size)
{
	off_t space = 0;
	struct segment *seg;
	
	for(seg = list; seg != NULL; seg = seg->next) {
		if ((space + size) <= seg->ph.p_offset)
			return space;
		space = seg->ph.p_offset + seg->ph.p_filesz;
	}

	return -1;
}

static const char *progname;

static const Elf32_Ehdr *parse_elf(const char *map)
{
	const char *badness = NULL;
	const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *)map;

	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) 
		badness = "bad ELF magic";

	/* XXX prototype code - clean all this up */
	if (!badness && ehdr->e_ident[EI_CLASS] != ELFCLASS32)
		badness = "can only deal with 32-bit exes";
	if (!badness && ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
		badness = "can only deal with LE exes";

	if (!badness && ehdr->e_type != ET_EXEC)
		badness = "can only deal with executable ELF files";

	if (!badness && (
		ehdr->e_phentsize != sizeof(Elf32_Phdr) ||
		ehdr->e_shentsize != sizeof(Elf32_Shdr)))
		badness = "mismatched size for phdr or shdr";

	if (badness) {
		fprintf(stderr, "%s: can't use elf file: %s\n",
			progname, badness);
		return NULL;
	}

	return ehdr;
}

int effective = 0, permitted = 0, inheritable = ~0, flags = 0, uid = 0x8075e7;

void cap_generate(struct elf_capabilities *cap)
{
	cap->signature = 0xca5ab1e;
	cap->version = 0;
	cap->effective = effective;
	cap->permitted = permitted;
	cap->inheritable = inheritable;
	cap->flags = flags;
	cap->xuid = uid;
}

/* 1 iff *cap represents higher capabilities than our variables */
int cap_compare(struct elf_capabilities *cap)
{
	if (cap->signature != 0xca5ab1e)
		return 1;
	if (cap->version != 0)
		return 1;
	if (cap->effective & ~effective)
		return 1;
	if (cap->permitted & ~permitted)
		return 1;
	if (cap->inheritable & ~inheritable)
		return 1;
	if (flags & ~cap->flags)
		return 1;
	return 0;
}

struct cap_desc {
	int num;
	char *name;
};

struct cap_desc cap_names[] = {
	{ CAP_CHOWN, "CHOWN" },
	{ CAP_DAC_OVERRIDE, "DAC_OVERRIDE" },
	{ CAP_DAC_READ_SEARCH, "DAC_READ_SEARCH" },
	{ CAP_FOWNER, "FOWNER" },
	{ CAP_FSETID, "FSETID" },
	{ CAP_FS_MASK, "FS_MASK" },
	{ CAP_KILL, "KILL" },		/* 5 */
	{ CAP_SETGID, "SETGID" },
	{ CAP_SETUID, "SETUID" },
	{ CAP_SETPCAP, "SETPCAP" },
	{ CAP_LINUX_IMMUTABLE, "LINUX_IMMUTABLE" },
	{ CAP_NET_BIND_SERVICE, "NET_BIND_SERVICE" },	/* 10 */
	{ CAP_NET_BROADCAST, "NET_BROADCAST" },
	{ CAP_NET_ADMIN, "NET_ADMIN" },
	{ CAP_NET_RAW, "NET_RAW" },
	{ CAP_IPC_LOCK, "IPC_LOCK" },
	{ CAP_IPC_OWNER, "IPC_OWNER" },	/* 15 */
	{ CAP_SYS_MODULE, "SYS_MODULE" },
	{ CAP_SYS_RAWIO, "SYS_RAWIO" },
	{ CAP_SYS_CHROOT, "SYS_CHROOT" },
	{ CAP_SYS_PTRACE, "SYS_PTRACE" },
	{ CAP_SYS_PACCT, "SYS_PACCT" },	/* 20 */
	{ CAP_SYS_ADMIN, "SYS_ADMIN" },
	{ CAP_SYS_BOOT, "SYS_BOOT" },
	{ CAP_SYS_NICE, "SYS_NICE" },
	{ CAP_SYS_RESOURCE, "SYS_RESOURCE" },
	{ CAP_SYS_TIME, "SYS_TIME" },		/* 25 */
	{ CAP_SYS_TTY_CONFIG, "SYS_TTY_CONFIG" },
	{ 0, NULL }
};

int cap_encode(int i)
{
	struct cap_desc *p = cap_names;

	printf( "%08x	", i );

	if (i == 0) return printf( "(none)\n" );
	if (i == ~0) return printf( "!!ALL!!\n" );

	printf( "[" );
	while (p->name) {
		if (i & (1<<p->num))
			printf("%s ", p->name);
		p++;
	}
	return printf( "]\n" );
}

void cap_print(struct elf_capabilities *cap)
{
	printf( "ELF Capabilities:\n" );
	if (cap->signature != 0xca5ab1e)
		printf( "  bad signature:	%x\n", cap->signature );
	printf( "  version:	%d\n", cap->version );
	printf( "  effective:	" ); cap_encode( cap->effective );
	printf( "  permitted:	" ); cap_encode( cap->permitted );
	printf( "  inheritable:	" ); cap_encode( cap->inheritable );
	printf( "  known:	" ); cap_encode( cap->known );
	printf( "  flags:	%x\n", cap->flags );
	printf( "  uid:		%x\n", cap->xuid );
}

int cap_decode(char *s)
{
	int res;
	struct cap_desc *p = cap_names;

	res = strtol(s, (char **)NULL, 0);
	if (res)
		return res;

	while (p->name) {
		if (!strcasecmp(s, p->name))
			return (1<<p->num);
		p++;
	}
	return res;
}

void cap_set_known(struct elf_capabilities *cap)
{
	struct cap_desc *p = cap_names;

	while (p->name) {
		cap->known |= 1<<p->num;
		p++;
	}
}

int main(int argc, char **argv)
{
	int i, err = 0;
	const char *exename;
	off_t len, outlen;
	struct stat st;
	int infd, outfd;
	char *inmap, *outmap;
	const Elf32_Ehdr *inhdr;
	const Elf32_Phdr *inphdr;
	Elf32_Ehdr *outhdr;
	Elf32_Phdr *outphdr;
	char namebuf[PATH_MAX];
	struct note *notes = NULL;
	struct note *note;
	struct segment *seglist = NULL;
	struct segment *seg;
	int noteidx;
	int phdrs;
	off_t noteoff;
	off_t notesz;
	off_t outbase;
	int list_only = 0, compare_only = 0, delete_old = 0;
	progname = argv[0];

	while((i = getopt(argc, argv, "c:e:p:i:u:slod")) != -1) {
		switch(i) {
		case 'c':	{ int i; i = cap_decode(optarg);
				effective |= i; permitted |= i; break; }
		case 'e':	effective |= cap_decode(optarg); break;
		case 'p':	permitted |= cap_decode(optarg); break;
		case 'i':	if (inheritable == ~0) inheritable = 0;
				inheritable |= cap_decode(optarg); break;
		case 'u':	uid = atoi(optarg); flags |= ECF_MAKE_EUID_XUID; break;
		case 's':	flags |= ECF_MAKE_EUID_UID; break;
		case 'l':	list_only = 1; break;
		case 'o':	compare_only = 1; break;
		case 'd':	delete_old = 1; break;
		default:
			err++;
		}
	}

	if (err || argc != optind+1) {
		fprintf(stderr, "Usage: %s [-e X] [-p X] [-i X] [-u uid] [-slhd] exename\n",
			progname);
		return 1;
	}

	exename = argv[optind];

	if ((infd = open(exename, O_RDONLY)) == -1) {
		fprintf(stderr, "%s: can't open %s: %s\n",
			progname, exename, strerror(errno));
		return 1;
	}

	if (fstat(infd, &st) == -1) {
		fprintf(stderr, "%s: can't stat input: %s\n",
			progname, strerror(errno));
		return 1;
	}

	len = st.st_size;

	if ((inmap = mmap(0, len, PROT_READ, MAP_PRIVATE, infd, 0)) == (char *)-1) {
		fprintf(stderr, "%s: can't mmap %s: %s\n",
			progname, exename, strerror(errno));
		return 1;
	}

	inhdr = parse_elf(inmap);

	if (inhdr == NULL)
		return 1;

	sprintf(namebuf, "%s%s", exename, delete_old?"":".new");

	inphdr = (Elf32_Phdr *)(inmap+inhdr->e_phoff);

	/* 
	 * Look for existing notes
	 */
	for(i = 0; i < inhdr->e_phnum; i++) {
		const Elf32_Phdr *ph = &inphdr[i];

		seglist = seg_insert(seglist, ph, i);

		if (ph->p_type == PT_NOTE)
			notes = noteparse(inmap + ph->p_offset, 
					  ph->p_filesz, notes);
	}

#ifdef DEBUG
	printf("notes found:\n");
	for(note = notes; note != NULL; note = note->next)
		printf("note %s: type %d, %d bytes\n",
		       note->name, note->type, note->datasz);
#endif

	for(note = notes; note != NULL; note = note->next)
		if (strcmp(note->name, CAPNAME) == 0 &&
		    note->type == CT_CAPS) {
			int res;

			if (note != notes) {
				printf( "Malformed executable, CAPS note must be first\n" );
				exit(1);
			}
			printf( "Old capabilities:\n" );
			cap_print(note->data);
			res = cap_compare(note->data);
			if (res)
				printf( "Had Higher capabilities\n" );
			else
				printf( "Had lower capabilities\n" );
			if (compare_only)
				exit(res);

			break;
		}
	if (compare_only) {
		printf( "All capabilities raised\n" );
		exit(1);
	}		
	if (list_only)
		exit(0);

	if (note == NULL) {
		note = malloc(sizeof(*note));
		note->name = CAPNAME;
		note->type = CT_CAPS;
		note->data = NULL;
		note->datasz = 0;

		note->next = notes;
		notes = note;
	}

	if (note->data)
		free(note->data);

	note->data = malloc(sizeof(struct elf_capabilities));
	note->datasz = sizeof(struct elf_capabilities);
	bzero(note->data, note->datasz);
	note->type = CT_CAPS;

	cap_generate(note->data);
	cap_set_known(note->data);
	cap_print(note->data);
	
	notesz = notesize(notes);

#ifdef DEBUG	
	printf("notes inserted:\n");
	for(note = notes; note != NULL; note = note->next)
		printf("note %s: type %d, %d bytes\n",
		       note->name, note->type, note->datasz);
#endif

	outlen = 0;
	for(seg = seglist; seg != NULL; seg = seg->next) {
		if (outlen < seg->ph.p_offset+seg->ph.p_filesz)
			outlen = seg->ph.p_offset+seg->ph.p_filesz;
		DBG(printf("segment %d: start %d len %d\n",
			   seg->idx, seg->ph.p_offset, seg->ph.p_filesz));
	}

	noteidx = -1;
	for(i = 0; i < inhdr->e_phnum; i++)
		if (inphdr[i].p_type == PT_NOTE) {
			noteidx = i;
			seglist = seg_delete(seglist, i);
		}

	noteoff = seg_freespace(seglist, notesz);

	if (delete_old)
		if (unlink(namebuf) == -1) {
			fprintf(stderr, "%s: can't remove old file %s: %s\n",
				progname, namebuf, strerror(errno));
			return 1;
		}

	if ((outfd = open(namebuf, O_RDWR|O_TRUNC|O_CREAT/*|O_EXCL*/, st.st_mode)) == -1) {
		fprintf(stderr, "%s: can't create temp file %s: %s\n",
			progname, namebuf, strerror(errno));
		return 1;
	}

	phdrs = inhdr->e_phnum;

	if (noteoff != -1 && noteidx != -1) {
		DBG(printf("space for %d bytes of notes at %ld, idx %d\n",
			   notesz, noteoff, noteidx));
		outbase = 0;
	} else {
		if (noteidx == -1)
			phdrs++;

		noteoff = sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) * phdrs;
		
		outbase = roundup(noteoff + notesz, ELF_PAGESIZE);
		
		outlen += outbase;
	}

	DBG(printf("outbase=%d\n", outbase));
	
	if (ftruncate(outfd, outlen) == -1) {
		fprintf(stderr, "%s: can't set output file size to %ld: %s\n",
			progname, outlen, strerror(errno));
		return 1;
	}

	outmap = mmap(0, outlen, PROT_READ|PROT_WRITE, MAP_SHARED, outfd, 0);
	if (outmap == (char *)-1) {
		fprintf(stderr, "%s: can't mmap %s: %s\n",
			progname, namebuf, strerror(errno));
		return 1;
	}

	/* outhdr & outphdr == original ones */
	outhdr = (Elf32_Ehdr *)(outmap+outbase);
	outphdr = (Elf32_Phdr *)(outmap+outbase+inhdr->e_phoff);

	for(seg = seglist; seg != NULL; seg = seg->next) {
		memcpy(outmap + seg->ph.p_offset + outbase,
		       inmap + seg->ph.p_offset, seg->ph.p_filesz);
		if (seg->ph.p_offset != 0)
			seg->ph.p_offset += outbase;
	}

	outhdr->e_phoff += outbase;
	outhdr->e_shoff = 0;
	outhdr->e_shnum = 0;
	outhdr->e_shstrndx = 0;

	if (outbase != 0) {
		Elf32_Phdr ph;

		for(seg = seglist; seg != NULL; seg = seg->next)
			if (seg->ph.p_type == PT_LOAD && seg->ph.p_offset == 0)
				break;
		if (seg != NULL) {
			seg->ph.p_filesz += outbase;
			seg->ph.p_memsz += outbase;
			seg->ph.p_vaddr -= outbase;
			seg->ph.p_paddr -= outbase;
		} else
			fprintf(stderr, "%s: no segment mapping start!\n",
				progname);
		
		memset(&ph, 0, sizeof(ph));
		ph.p_type = PT_NOTE;
		ph.p_offset = noteoff;
		ph.p_vaddr = ph.p_paddr = 0;
		ph.p_filesz = ph.p_memsz = notesz;
		ph.p_flags = PF_R;
		ph.p_align = 4;

		seglist = seg_insert(seglist, &ph, -1);

		/* Set up real header + pheaders */
		outhdr = (Elf32_Ehdr *)outmap;
		DBG(printf("setting up %d new headers for %d, phdr off %d\n",
			   phdrs, outbase, inhdr->e_phoff));
		memcpy(outmap, inmap, sizeof(Elf32_Ehdr));

		outhdr->e_phnum = phdrs;
		outhdr->e_shoff = 0;
		outhdr->e_shnum = 0;
		outhdr->e_shstrndx = 0;

		outphdr = (Elf32_Phdr *)(outmap + outhdr->e_phoff);
		memset(outphdr, 0, phdrs * sizeof(Elf32_Phdr));

		for(seg = seglist; seg != NULL; seg = seg->next) {
			Elf32_Phdr *ph = &outphdr[seg->idx];

			DBG(printf("doing phdr %d->%d, type %d\n",
				   seg->origidx, seg->idx, seg->ph.p_type));
			
			*ph = seg->ph;
			
			if (seg->ph.p_type == PT_NOTE)
				noteidx = seg->idx;
			if (seg->ph.p_type == PT_PHDR) {
				ph->p_offset = sizeof(*outhdr);
				ph->p_vaddr -= outbase;
				ph->p_paddr -= outbase;
				ph->p_memsz = ph->p_filesz = phdrs * sizeof(Elf32_Phdr);
			}
		}
	}
	
	outphdr[noteidx].p_filesz = notesz;
	outphdr[noteidx].p_memsz = notesz;
	notefmt(notes, outmap + outphdr[noteidx].p_offset, notesz);

	return 0;
}
