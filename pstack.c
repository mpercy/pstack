/*
 pstack.c -- asynchronous stack trace of a running process
 Copyright (c) 1999 Ross Thompson
 Copyright (c) 2001, 2003 Red Hat, Inc.

 Original Author: Ross Thompson <ross@whatsis.com>
 Critical bug fix: Tim Waugh

*/

/*
 This file is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* RESTRICTIONS:

   pstack currently works only on Linux, only on an x86 machine running
   32 bit ELF binaries (64 bit not supported).  Also, for symbolic
   information, you need to use a GNU compiler to generate your
   program, and you can't strip symbols from the binaries.  For thread
   information to be dumped, you have to use the debug-aware version
   of libpthread.so.  (To check, run 'nm' on your libpthread.so, and
   make sure that the symbol "__pthread_threads_debug" is defined.)
*/

#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <link.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

static int thePid; /* pid requested by caller. */
static struct {
  int found;
  int *pids; /* pid[0] is dad, pid[1] is manager */
  int *attached; /* pid[i] is attached? 1 = yes, 0 = no */
  int npids;
} threads;

/* ------------------------------ */

static int attach(int pid)
{
  int status;

  errno = 0;
  ptrace(PTRACE_ATTACH, pid, 0, 0);

  if (errno)
    return errno;

  waitpid (pid, &status, WUNTRACED);

  /* If we failed due to an ECHILD, then retry with the __WCLONE
     flag.  Note we loop as the the PID we get back may not be
     one we care about.  */
  if (errno == ECHILD) {
    int x;

    errno = 0;
    while (1) {
      x = waitpid (-1, &status, (__WCLONE));

      if (x == pid || x < 0 || errno != 0) break;
    }
  }

  return errno;
}

static int detachall(void)
{
  int i;

  /* First detach from all the threads, except the one we initially
     attached to.  Note that the PTRACE_DETACH will continue the
     thread, so there is no need to issue a separate PTRACE_CONTINUE
     call.  */
  if (threads.found) {
    for (i = 0; i < threads.npids; i++) {
      if (threads.pids[i] != thePid && threads.attached[i]) {
        errno = 0;
        ptrace(PTRACE_DETACH, threads.pids[i], 0, 0);
        if (errno) perror("detach");
      }
    }
  }

  /* Now attach from the thread we initially attached to.  Note that
     the PTRACE_DETACH will continue the thread, so there is no need
     is issue a separate PTRACE_CONTINUE call.  */
  ptrace(PTRACE_DETACH, thePid, 0, 0);

  return errno;
}

static void handle_signal (int signum)
{
  signal (signum, SIG_DFL);
  psignal (signum, "pstack signal received");
  if (thePid) detachall();
  exit (1);
}

static void quit(char *msg)
{
  fputs(msg, stderr);
  fputc('\n', stderr);
  if (thePid) detachall();
  exit(1);
}

/* ------------------------------ */

static Elf32_Addr DebugInfo;

typedef struct _t_Symbols {
  struct _t_Symbols *next;
  char *name;
  Elf32_Sym *symbols;
  int nsyms;
  char *strings;
  int strslen, noffsets;
  Elf32_Addr baseAddr;
  Elf32_Dyn *dynamic;
  int ndyns;
} *Symbols;

static Symbols allSyms;

static Symbols newSyms(const char *name)
{
  Symbols syms = (Symbols) calloc(sizeof(struct _t_Symbols), 1);

  if (!syms) quit("Out of memory");
  syms->next = allSyms;
  allSyms = syms;
  syms->name = strdup(name);

  return syms;
}

static void deleteSyms(Symbols syms)
{
  Symbols s2;

  if (syms == allSyms) allSyms = syms->next;
  else {
    for (s2 = allSyms; s2 && s2->next != syms; s2 = s2->next);
    if (s2) s2->next = syms->next;
  }
  if (syms->symbols) free(syms->symbols);
  if (syms->strings) free(syms->strings);
  if (syms->dynamic) free(syms->dynamic);
  if (syms->name)    free(syms->name);
  free(syms);
}

static const Elf32_Sym *lookupSymInTable(const char *name, Symbols syms)
{
  Elf32_Sym *sym;
  int i;

  for (i = 0, sym = syms->symbols; i < syms->nsyms; i++, sym++) {
    if (!strcmp(name, &syms->strings[sym->st_name]))
      return sym;
  }

  return 0;
}

static void findCodeAddress(Elf32_Addr addr, Elf32_Sym **ans,
                            Symbols *symtab)
{
  Elf32_Sym *sym;
  Symbols tab;
  int i;

  for (tab = allSyms, *ans = 0, *symtab = 0; tab; tab = tab->next) {
    if (addr < tab->baseAddr) continue;
    for (sym = tab->symbols, i = 0; i < tab->nsyms; i++, sym++) {
      if (sym->st_value <= addr && sym->st_shndx != SHN_UNDEF &&
          sym->st_shndx < tab->noffsets &&
          ELF32_ST_TYPE(sym->st_info) == STT_FUNC &&
          (!*ans || (*ans)->st_value < sym->st_value))
        *ans = sym, *symtab = tab;
    }
  }
}

/* ------------------------------ */

static void resetData(void)
{
  Symbols syms, ns;

  if (threads.pids) free(threads.pids);
  if (threads.attached) free(threads.attached);
  threads.pids = 0;
  threads.attached = 0;
  threads.found = 0;

  for (syms = allSyms; syms; syms = ns) {
    ns = syms->next;
    deleteSyms(syms);
  }
}

/* ------------------------------ */

static const Elf32_Sym *findLocalSym(const char *name, Symbols syms)
{
  const Elf32_Sym *sym = lookupSymInTable(name, syms);

  return (!sym || sym->st_shndx == SHN_UNDEF ||
          sym->st_shndx >= syms->noffsets) ? 0 : sym;
}

static int readSym(Symbols syms, int pid, const char *name, int *val)
{
  const Elf32_Sym *sym;

  if (!(sym = findLocalSym(name, syms))) return 0;
  errno = 0;
  *val = ptrace(PTRACE_PEEKDATA, pid, sym->st_value, 0);
  if (errno) {
    perror("ptrace");
    quit("Could not read thread debug info.");
  }
  return 1;
}

static void checkForThreads(Symbols syms, int pid)
{
  const Elf32_Sym *handles;
  int i, tpid, hsize, descOff, pidOff, numPids, *pptr;
  Elf32_Addr descr;

  if (!findLocalSym("__pthread_threads_debug", syms) ||
      !(handles = findLocalSym("__pthread_handles", syms)) ||
      !readSym(syms, pid, "__pthread_sizeof_handle", &hsize) ||
      !readSym(syms, pid, "__pthread_offsetof_descr", &descOff) ||
      !readSym(syms, pid, "__pthread_offsetof_pid", &pidOff) ||
      !readSym(syms, pid, "__pthread_handles_num", &numPids) ||
      numPids == 1 ||
      !(threads.pids = (int *) calloc(numPids + 2, sizeof(int))) ||
      !(threads.attached = (int *) calloc(numPids + 2, sizeof(int)))) {
    if (threads.pids) {
      free(threads.pids);
      threads.pids = 0;
    }
    if (threads.attached) {
      free(threads.attached);
      threads.attached = 0;
    }
    return;
  }
  errno = 0;

  for (pptr = &threads.pids[0], i = 0; i < numPids && !errno; i++) {
    descr = ptrace(PTRACE_PEEKDATA, pid,
                   handles->st_value + (i * hsize) + descOff, 0);
    if (!descr && i == 0)
      /* The initial thread's descriptor was not initialized yet.  */
      *pptr++ = pid;
    else if (descr && !errno) {
      tpid = ptrace(PTRACE_PEEKDATA, pid, descr + pidOff, 0);
      if (!errno)
        *pptr++ = tpid;
    }
  }
  threads.npids = pptr - threads.pids;

  if (errno) {
    perror("ptrace");
    quit("Could not read thread debug info.");
  }

  threads.found = 1;

  for (i = 0; i < threads.npids; i++) {
    if (threads.pids[i] && threads.pids[i] != pid) {
      if (attach(threads.pids[i]) != 0)
        printf("Could not attach to thread %d.\n", threads.pids[i]);
      else threads.attached[i] = 1;
    } else if (threads.pids[i] == pid) {
      threads.attached[i] = 1;
    }

  }
}

/* ------------------------------ */

static void verify_ident(Elf32_Ehdr *hdr)
{
  if (memcmp(&hdr->e_ident[EI_MAG0], ELFMAG, SELFMAG))
    quit("Bad magic number.");
  if (hdr->e_ident[EI_CLASS] != ELFCLASS32)
    quit("only 32 bit objects supported.");
  if (hdr->e_ident[EI_DATA] != ELFDATA2LSB)
    quit("big endian object files not supported.");
  if (hdr->e_ident[EI_VERSION] != EV_CURRENT ||
      hdr->e_version != EV_CURRENT)
    quit("Unsupported ELF format version.");
  if (hdr->e_machine != EM_386)
    quit("Not an IA32 executable.");
}

static int find_stables(Elf32_Ehdr *hdr, int fd, Symbols syms)
{
  int i, idx, spot;
  Elf32_Shdr shdr;

  spot = hdr->e_shoff;
  if (lseek(fd, spot, SEEK_SET) != spot) quit("seek failed.");

  memset(&shdr, 0, sizeof(shdr));

  syms->noffsets = hdr->e_shnum;

  for (idx = 0; idx < hdr->e_shnum; idx++) {
    if (read(fd, &shdr, hdr->e_shentsize) != hdr->e_shentsize)
      quit("premature eof.");
    spot += hdr->e_shentsize;
    switch (shdr.sh_type) {
     case SHT_SYMTAB:
      syms->nsyms = shdr.sh_size / sizeof(Elf32_Sym);

      if (!(syms->symbols = (Elf32_Sym *) malloc(shdr.sh_size)))
        quit("Could not allocate symbol table.");

      if (lseek(fd, shdr.sh_offset, SEEK_SET) != shdr.sh_offset ||
          read(fd, syms->symbols, shdr.sh_size) != shdr.sh_size)
        quit("Could not read symbol table.");

      i = hdr->e_shoff + shdr.sh_link * hdr->e_shentsize;
      if (lseek(fd, i, SEEK_SET) != i)
        quit("Could not seek and find.");
      if (read(fd, &shdr, hdr->e_shentsize) != hdr->e_shentsize)
        quit("Could not read string table section header.");
      if (!(syms->strings = malloc(shdr.sh_size)))
        quit("Could not allocate string table.");
      if (lseek(fd, shdr.sh_offset, SEEK_SET) != shdr.sh_offset ||
          read(fd, syms->strings, shdr.sh_size) != shdr.sh_size)
        quit("Could not read string table.");
      lseek(fd, spot, SEEK_SET);
      break;
     case SHT_DYNAMIC:
      syms->ndyns = shdr.sh_size / sizeof(Elf32_Dyn);
      if (!(syms->dynamic = (Elf32_Dyn *) malloc(shdr.sh_size)))
        quit("Out of memory.");
      if (lseek(fd, shdr.sh_offset, SEEK_SET) != shdr.sh_offset ||
          read(fd, syms->dynamic, shdr.sh_size) != shdr.sh_size)
        quit("Could not read dynamic table.");
      lseek(fd, spot, SEEK_SET);
      break;
    }
  }

  return (syms->nsyms > 0);
}

static Symbols loadSyms(const char *fname)
{
  Elf32_Ehdr hdr;
  int fd;
  Symbols syms;

  syms = newSyms(fname);
  if ((fd = open(fname, O_RDONLY)) < 0)
  {
    fprintf(stderr, "'%s': ", fname);
    perror("opening object file");
    quit("Could not open object file.");
  }
  read(fd, &hdr, sizeof(hdr));
  verify_ident(&hdr);
  if (!find_stables(&hdr, fd, syms)) {
    deleteSyms(syms);
    syms = 0;
  }
  close(fd);

  return syms;
}

static void readDynoData(Symbols syms, int pid)
{
  int val, done;
  Elf32_Addr addr;
  const Elf32_Sym *dyn = lookupSymInTable("_DYNAMIC", syms);

  for (errno = done = 0, addr = dyn->st_value; !done && !errno; addr += 8) {
    val = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    if (errno) break;
    switch (val) {
     case DT_NULL: done = 1; break;
     case DT_DEBUG:
      // point to the r_debug struct -- see link.h
      DebugInfo = (Elf32_Addr) ptrace(PTRACE_PEEKDATA, pid, addr + 4, 0);
      // point to the head of the link_map chain.
      DebugInfo = (Elf32_Addr) ptrace(PTRACE_PEEKDATA, pid, DebugInfo + 4, 0);
      break;
    }
  }
  if (errno) {
    perror("pstack");
    quit("failed to read target.");
  }
}

static void resolveSymbols(Symbols syms, int offset)
{
  Elf32_Sym *sym;
  int i;

  syms->baseAddr = offset;

  for (i = 0, sym = syms->symbols; i < syms->nsyms; i++, sym++) {
    if (sym->st_shndx && sym->st_shndx < syms->noffsets) {
      sym->st_value += offset;
    }
  }
}

static void loadString(int pid, int addr, char *dp, int bytes)
{
  long *lp = (long *) dp, nr;

  memset(dp, 0, bytes);
  errno = 0;

  addr = ptrace(PTRACE_PEEKDATA, pid, addr, 0);

  for (nr = 0, errno = 0; !errno && bytes > 4 && strlen(dp) == nr;
       addr += 4, bytes -= 4, nr += 4) {
    *lp++ = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
  }

  if (errno) {
    perror("ptrace");
    quit("loadString failed.");
  }
}

#define OFFSET(f, s) ((int) ((char *) &(s).f - (char *) &(s)))
static void readLinkMap(int pid, Elf32_Addr base,
                        struct link_map *lm, char *name, int namelen)
{
  errno = 0;

  /* base address */
  lm->l_addr = (Elf32_Addr) ptrace(PTRACE_PEEKDATA, pid,
                                   base + OFFSET(l_addr, *lm), 0);
  /* next element of link map chain */
  if (!errno)
    lm->l_next = (struct link_map *) ptrace(PTRACE_PEEKDATA, pid,
                                            base + OFFSET(l_next, *lm), 0);
  if (errno) {
    perror("ptrace");
    quit("can't read target.");
  }

  loadString(pid, base + OFFSET(l_name, *lm), name, namelen);
}

static void loadSymbols(int pid)
{
  char buf[256];
  Symbols syms;
  struct link_map lm;

  sprintf(buf, "/proc/%d/exe", pid);
  if (!(syms = loadSyms(buf))) {
    fputs("(No symbols found)\n", stdout);
    return;
  }

  readDynoData(syms, pid);
  readLinkMap(pid, DebugInfo, &lm, buf, sizeof(buf));

  for ( ; lm.l_next; ) {
    readLinkMap(pid, (Elf32_Addr) lm.l_next, &lm, buf, sizeof(buf));
    if (!(syms = loadSyms(buf))) {
	printf("(No symbols found in %s)\n", buf);
	continue;
    }
    resolveSymbols(syms, lm.l_addr);
    if (!threads.found) checkForThreads(syms, pid);
  }
}

/* ------------------------------ */

static void print_pc(Elf32_Addr addr)
{
  Elf32_Sym *sym;
  Symbols syms;

  findCodeAddress(addr, &sym, &syms);

  if (!sym)
    printf("0x%08lx: ????", (unsigned long) addr);
  else if (sym->st_value < addr)
    printf("0x%08lx: %s + 0x%x", (unsigned long) addr,
	   &syms->strings[sym->st_name], addr - sym->st_value);
  else
    printf("0x%08lx: %s", (unsigned long) addr, &syms->strings[sym->st_name]);
}

/* ------------------------------ */

#define MAXARGS 6

static int crawl(int pid)
{
  unsigned long pc, fp, nextfp, nargs, i, arg;

  errno = 0;
  fp = -1;

  pc = ptrace(PTRACE_PEEKUSER, pid, EIP * 4, 0);
  if (!errno)
    fp = ptrace(PTRACE_PEEKUSER, pid, EBP * 4, 0);

  if (!errno) {
    print_pc(pc);
    for ( ; !errno && fp; ) {
      nextfp = ptrace(PTRACE_PEEKDATA, pid, fp, 0);
      if (errno) break;

      nargs = (nextfp - fp - 8) / 4;
      if (nargs > MAXARGS) nargs = MAXARGS;
      if (nargs > 0) {
        fputs(" (", stdout);
        for (i = 1; i <= nargs; i++) {
          arg = ptrace(PTRACE_PEEKDATA, pid, fp + 4 * (i + 1), 0);
          if (errno) break;
          printf("%lx", arg);
          if (i < nargs) fputs(", ", stdout);
        }
        fputc(')', stdout);
        nargs = nextfp - fp - 8 - (4 * nargs);
        if (!errno && nargs > 0) printf(" + %lx\n", nargs);
        else fputc('\n', stdout);
      } else fputc('\n', stdout);

      if (errno || !nextfp) break;
      pc = ptrace(PTRACE_PEEKDATA, pid, fp + 4, 0);
      fp = nextfp;
      if (errno) break;
      print_pc(pc);
    }
  }

  if (errno) perror("crawl");
  return errno;
}

/* ------------------------------ */

static char cmd[128];

static char *cmdLine(int pid)
{
  int fd, len, i;

  fd = -1;
  sprintf(cmd, "/proc/%d/cmdline", pid);
  if ((fd = open(cmd, O_RDONLY)) >= 0 &&
      (len = read(fd, cmd, sizeof(cmd))) > 0) {
    for (i = 0; i < len; i++) if (!cmd[i]) cmd[i] = ' ';
    for ( ; len > 0 && cmd[len - 1] <= ' '; len--);
    cmd[len] = 0;
    if (len >= sizeof(cmd) - 4)
      strcpy(&cmd[sizeof(cmd) - 4], "...");
  }
  if (fd < 0 || len <= 0) strcpy(cmd, "(command line?)");
  if (fd >= 0) close(fd);

  return cmd;
}

void usage(const char *argv0, const char *param)
{
	fprintf(stderr, "Invalid parameter '%s'.\n", param);
	fprintf(stderr, "Usage: %s <pid> [one or more]\n", argv0);
	exit(1);
}

int main(int argc, char **argv)
{
  int i;
  const char *argv0 = argv[0];

  /* Arrange to detach if we get an unexpected signal.  This prevents
     threads from being left in a suspended state if (for example) we
     try to get a stack trace from a threaded process which has
     been stripped.  */
  for (i = 0; i < NSIG; i++)
    if (i != SIGCHLD)
      signal (i, handle_signal);

  for (argc--, argv++; argc > 0; argc--, argv++) {
    char *endptr = NULL;
    thePid = strtol(*argv, &endptr, 0);
    if (!*argv || *endptr || errno==ERANGE)
	    usage(argv0, *argv);
    if (!thePid || thePid == getpid()) {
      fprintf(stderr, "Invalid PID %d\n", thePid);
      continue;
    }

    if (attach(thePid) != 0) {
      fprintf(stderr, "Could not attach to target %d\n", thePid);
    } else {
      printf("\n%d: %s\n", thePid, cmdLine(thePid));
      loadSymbols(thePid);
      if (threads.found) {
        for (i = 0; i < threads.npids; i++) {
          if (threads.attached[i]) {
            printf("----- Thread %d -----\n", threads.pids[i]);
            if (crawl(threads.pids[i]) != 0)
              fprintf(stderr, "Error tracing through thread %d\n",
                      threads.pids[i]);
          }
        }
      } else if (crawl(thePid) != 0)
        fprintf(stderr, "Error tracing through process %d\n", thePid);
    }

    detachall();
    resetData();
  }

  exit(0);
}
