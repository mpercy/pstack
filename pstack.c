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
#include <sys/user.h>

#include <fcntl.h>
#include <link.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>



/*************************************
 *    Architecture dependant code    *
 *************************************/

/* Word size */
#if __WORDSIZE == 64
#define uintN_t uint64_t
#define ElfN_Ehdr Elf64_Ehdr
#define ElfN_Shdr Elf64_Shdr
#define ElfN_Addr Elf64_Addr
#define ElfN_Sym Elf64_Sym
#define ElfN_Dyn Elf64_Dyn
#define ElfN_Off Elf64_Off
#define ELFCLASSN ELFCLASS64
#define ELFN_ST_TYPE ELF64_ST_TYPE
#define INT_RANGE_STR "64"
#else
#define uintN_t uint32_t
#define ElfN_Ehdr Elf32_Ehdr
#define ElfN_Shdr Elf32_Shdr
#define ElfN_Addr Elf32_Addr
#define ElfN_Sym Elf32_Sym
#define ElfN_Dyn Elf32_Dyn
#define ElfN_Off Elf32_Off
#define ELFCLASSN ELFCLASS32
#define ELFN_ST_TYPE ELF32_ST_TYPE
#define INT_RANGE_STR "32"
#endif

/* Endianness */
#ifdef __ORDER_LITTLE_ENDIAN__
#define ELF_EI_DATA ELFDATA2LSB
#define ELF_ENDIANNESS_ERRSTR "big"
#elif defined(__ORDER_BIG_ENDIAN__)
#define ELF_EI_DATA ELFDATA2MSB
#define ELF_ENDIANNESS_ERRSTR "little"
#else
#include <endian.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ELF_EI_DATA ELFDATA2LSB
#define ELF_ENDIANNESS_ERRSTR "big"
#else
#define ELF_EI_DATA ELFDATA2MSB
#define ELF_ENDIANNESS_ERRSTR "little"
#endif
#endif

/* Machine dependant: ELF machine name, registers name and stack layout */
#if defined(__i386__) || defined(__x86_64__)
#if defined(__i386__) /* x86-32 */
#define ELF_MACHINE EM_386
#define PROGRAM_COUNTER(regs) (regs.eip)
#define FRAME_POINTER(regs) (regs.ebp)
#else /* x86-64 */
#define ELF_MACHINE EM_X86_64
#define PROGRAM_COUNTER(regs) (regs.rip)
#define FRAME_POINTER(regs) (regs.rbp)
#endif /* x86-{32,64} */
#define NEXT_FRAME_POINTER_ADDR(fp) (fp)
#define NEXT_PROGRAM_COUNTER_ADDR(fp) ((fp) + __SIZEOF_POINTER__)
#define DECLARE_REGS_STRUCT(regs) struct user_regs_struct regs
#elif defined(__ARMEL__) /* armel */
#define ELF_MACHINE EM_ARM
#define PROGRAM_COUNTER(regs) (regs.ARM_pc)
#define FRAME_POINTER(regs) (regs.ARM_fp)
#define NEXT_FRAME_POINTER_ADDR(fp) ((fp) - __SIZEOF_POINTER__)
#define NEXT_PROGRAM_COUNTER_ADDR(fp) (fp)
#define DECLARE_REGS_STRUCT(regs) struct user_regs regs
#elif defined(__ppc64__) || defined(__alpha__) || defined(__ia64__) || defined(s390x__)
#error Not (yet) supported architecture, patches welcomes :-)
#else
#error Not (yet) recognized architecture, patches welcomes :-)
#endif

#define NB_ARGS(fp, nextfp) \
	(((nextfp) - (fp) - (2 * __SIZEOF_POINTER__)) / __SIZEOF_POINTER__)
#define ARG_NMBR(fp, i) ((fp) + __SIZEOF_POINTER__ * ((i) + 1))
#define NB_ARGS_REMAINING(fp, nextfp, nargs) \
	((nextfp) - (fp) - (2 * __SIZEOF_POINTER__) - \
	(__SIZEOF_POINTER__ * nargs))



/***************************************
 *    Architecture independant code    *
 ***************************************/

static pid_t thePid; /* pid requested by caller. */
static struct {
  int found;
  pid_t *pids; /* pid[0] is dad, pid[1] is manager */
  int *attached; /* pid[i] is attached? 1 = yes, 0 = no */
  int npids;
} threads;

/* ------------------------------ */

static int attach(pid_t pid)
{
  int status;

  errno = 0;
  if (-1 == ptrace(PTRACE_ATTACH, pid, 0, 0))
    return errno;

  /* If we failed due to an ECHILD, then retry with the __WCLONE
     flag.  Note we loop as the the PID we get back may not be
     one we care about.  */
  if (-1 == waitpid(pid, &status, WUNTRACED) && errno == ECHILD) {
    pid_t x;

    while (1) {
      x = waitpid (-1, &status, (__WCLONE));

      if (x == pid || x < 0) break;
    }
    if (x) errno = 0;
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
        if (-1==ptrace(PTRACE_DETACH, threads.pids[i], 0, 0)) {
          perror("detach");
	}
      }
    }
  }

  /* Now attach from the thread we initially attached to.  Note that
     the PTRACE_DETACH will continue the thread, so there is no need
     is issue a separate PTRACE_CONTINUE call.  */
  if (-1 == ptrace(PTRACE_DETACH, thePid, 0, 0)) {
    perror("detach");
    return errno;
  }
  return 0;
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

static ElfN_Addr DebugInfo;

typedef struct _t_Symbols {
  struct _t_Symbols *next;
  char *name;
  ElfN_Sym *symbols;
  int nsyms;
  char *strings;
  int strslen, noffsets;
  ElfN_Addr baseAddr;
  ElfN_Dyn *dynamic;
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

static const ElfN_Sym *lookupSymInTable(const char *name, Symbols syms)
{
  ElfN_Sym *sym;
  int i;

  for (i = 0, sym = syms->symbols; i < syms->nsyms; i++, sym++) {
    if (!strcmp(name, &syms->strings[sym->st_name]))
      return sym;
  }

  return 0;
}

static void findCodeAddress(ElfN_Addr addr, ElfN_Sym **ans,
                            Symbols *symtab)
{
  ElfN_Sym *sym;
  Symbols tab;
  int i;

  for (tab = allSyms, *ans = 0, *symtab = 0; tab; tab = tab->next) {
    if (addr < tab->baseAddr) continue;
    for (sym = tab->symbols, i = 0; i < tab->nsyms; i++, sym++) {
      if (sym->st_value <= addr && sym->st_shndx != SHN_UNDEF &&
          sym->st_shndx < tab->noffsets &&
          ELFN_ST_TYPE(sym->st_info) == STT_FUNC &&
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

static const ElfN_Sym *findLocalSym(const char *name, Symbols syms)
{
  const ElfN_Sym *sym = lookupSymInTable(name, syms);

  return (!sym || sym->st_shndx == SHN_UNDEF ||
          sym->st_shndx >= syms->noffsets) ? 0 : sym;
}

static int readSym(Symbols syms, int pid, const char *name, int *val)
{
  const ElfN_Sym *sym;

  if (!(sym = findLocalSym(name, syms))) return 0;
  errno = 0;
  *val = ptrace(PTRACE_PEEKDATA, pid, sym->st_value, 0);
  if (-1 == *val && errno) {
    perror("ptrace");
    quit("Could not read thread debug info.");
  }
  return 1;
}

static void checkForThreads(Symbols syms, int pid)
{
  const ElfN_Sym *handles;
  int i, tpid, hsize, descOff, pidOff, numPids, *pptr;
  int error_occured = 0;
  ElfN_Addr descr;

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
    else if (descr != (ElfN_Addr) -1 || !errno) {
      tpid = ptrace(PTRACE_PEEKDATA, pid, descr + pidOff, 0);
      if (tpid != -1 || !errno)
        *pptr++ = tpid;
      else error_occured = 1;
    } else error_occured = 1;
  }
  threads.npids = pptr - threads.pids;

  if (error_occured) {
    perror("ptrace");
    quit("Could not read thread debug info.");
  }

  threads.found = 1;

  for (i = 0; i < threads.npids; i++) {
    if (threads.pids[i] && threads.pids[i] != pid) {
      if (attach(threads.pids[i]) != 0)
        printf("Could not attach to thread %d: %s.\n", threads.pids[i], strerror(errno));
      else threads.attached[i] = 1;
    } else if (threads.pids[i] == pid) {
      threads.attached[i] = 1;
    }

  }
}

/* ------------------------------ */

static void verify_ident(ElfN_Ehdr *hdr)
{
  if (memcmp(&hdr->e_ident[EI_MAG0], ELFMAG, SELFMAG))
    quit("Bad magic number.");
  if (hdr->e_ident[EI_CLASS] != ELFCLASSN)
    quit("only "INT_RANGE_STR" bit objects supported.");
  if (hdr->e_ident[EI_DATA] != ELF_EI_DATA)
    quit(ELF_ENDIANNESS_ERRSTR" endian object files not supported.");
  if (hdr->e_ident[EI_VERSION] != EV_CURRENT ||
      hdr->e_version != EV_CURRENT)
    quit("Unsupported ELF format version.");
  if (hdr->e_machine != ELF_MACHINE)
    quit("Not an IA32 executable.");
}

static int find_stables(ElfN_Ehdr *hdr, int fd, Symbols syms)
{
  int i, idx, spot;
  ElfN_Shdr shdr;

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
      syms->nsyms = shdr.sh_size / sizeof(ElfN_Sym);

      if (!(syms->symbols = (ElfN_Sym *) malloc(shdr.sh_size)))
        quit("Could not allocate symbol table.");

      if ((ElfN_Off) lseek(fd, shdr.sh_offset, SEEK_SET) != shdr.sh_offset ||
          (uintN_t) read(fd, syms->symbols, shdr.sh_size) != shdr.sh_size)
        quit("Could not read symbol table.");

      i = hdr->e_shoff + shdr.sh_link * hdr->e_shentsize;
      if (lseek(fd, i, SEEK_SET) != i)
        quit("Could not seek and find.");
      if (read(fd, &shdr, hdr->e_shentsize) != hdr->e_shentsize)
        quit("Could not read string table section header.");
      if (!(syms->strings = malloc(shdr.sh_size)))
        quit("Could not allocate string table.");
      if ((ElfN_Off) lseek(fd, shdr.sh_offset, SEEK_SET) != shdr.sh_offset ||
          (uintN_t) read(fd, syms->strings, shdr.sh_size) != shdr.sh_size)
        quit("Could not read string table.");
      lseek(fd, spot, SEEK_SET);
      break;
     case SHT_DYNAMIC:
      syms->ndyns = shdr.sh_size / sizeof(ElfN_Dyn);
      if (!(syms->dynamic = (ElfN_Dyn *) malloc(shdr.sh_size)))
        quit("Out of memory.");
      if ((ElfN_Off) lseek(fd, shdr.sh_offset, SEEK_SET) != shdr.sh_offset ||
          (uintN_t) read(fd, syms->dynamic, shdr.sh_size) != shdr.sh_size)
        quit("Could not read dynamic table.");
      lseek(fd, spot, SEEK_SET);
      break;
    }
  }

  return (syms->nsyms > 0);
}

static Symbols loadSyms(const char *fname)
{
  ElfN_Ehdr hdr;
  int fd;
  Symbols syms;

  if (*fname == '\0')
    return (Symbols) 0;
  syms = newSyms(fname);
  if ((fd = open(fname, O_RDONLY)) < 0)
  {
    fprintf(stderr, "'%s': ", fname);
    perror("opening object file");
    quit("Could not open object file.");
  }
  if (read(fd, &hdr, sizeof(hdr)) < (int) sizeof(hdr))
  {
    fprintf(stderr, "'%s': ", fname);
    perror("reading object file ELF header");
    quit("Could not read object file ELF header.");
  }
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
  int done;
  long val;
  ElfN_Dyn dyn_elem;
  ElfN_Addr addr;
  const ElfN_Sym *dyn = lookupSymInTable("_DYNAMIC", syms);

  if (!dyn) quit("could not find _DYNAMIC symbol");
  for (errno = done = 0, addr = dyn->st_value; !done && !errno;
       addr += sizeof dyn_elem) {
    val = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    if (val == -1 && errno) break;
    dyn_elem.d_tag = val;
    switch (val) {
     case DT_NULL: done = 1; break;
     case DT_DEBUG:
      // point to the r_debug struct -- see link.h
      dyn_elem.d_un.d_ptr = (ElfN_Addr) ptrace(PTRACE_PEEKDATA, pid,
                  addr + sizeof(dyn_elem.d_tag), 0);
      DebugInfo = dyn_elem.d_un.d_ptr + offsetof(struct r_debug,r_map);
      // point to the head of the link_map chain.
      DebugInfo = (ElfN_Addr) ptrace(PTRACE_PEEKDATA, pid,
                  DebugInfo, 0);
      break;
    }
  }
  if (!done && errno) {
    perror("pstack");
    quit("failed to read target.");
  }
}

static void resolveSymbols(Symbols syms, int offset)
{
  ElfN_Sym *sym;
  int i;

  syms->baseAddr = offset;

  for (i = 0, sym = syms->symbols; i < syms->nsyms; i++, sym++) {
    if (sym->st_shndx && sym->st_shndx < syms->noffsets) {
      sym->st_value += offset;
    }
  }
}

static void loadString(pid_t pid, ElfN_Addr addr, char *dp, unsigned int bytes)
{
  long *lp = (long *) dp;
  unsigned int nr;
  int error_occured = 0;

  memset(dp, 0, bytes);
  errno = 0;

  addr = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
  if (addr == (ElfN_Addr) -1 && errno)
    error_occured = 0;

  for (nr = 0; bytes > sizeof(long) && strlen(dp) == nr;
       addr += sizeof(long), bytes -= sizeof(long), nr += sizeof(long)) {
    long lp_val = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    if (lp_val == -1 && errno) {
      error_occured = 0;
      break;
    }
    *lp++ = lp_val;
  }

  if (error_occured) {
    perror("ptrace");
    quit("loadString failed.");
  }
}

static void readLinkMap(int pid, ElfN_Addr base,
                        struct link_map *lm, char *name, unsigned int namelen)
{
  /* base address */
  lm->l_addr = (ElfN_Addr) ptrace(PTRACE_PEEKDATA, pid,
                                   base + offsetof(struct link_map,l_addr), 0);
  /* next element of link map chain */
  if (-1 != (long) lm->l_addr || !errno)
    lm->l_next = (struct link_map *) ptrace(PTRACE_PEEKDATA, pid,
                                            base + offsetof(struct link_map, l_next), 0);
  if ((-1 == (long) lm->l_addr || -1 == (long) lm->l_next) && errno) {
    perror("ptrace");
    quit("can't read target.");
  }

  loadString(pid, base + offsetof(struct link_map, l_name), name, namelen);
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
    readLinkMap(pid, (ElfN_Addr) lm.l_next, &lm, buf, sizeof(buf));
    if (!(syms = loadSyms(buf))) {
	printf("(No symbols found in %s)\n", buf);
	continue;
    }
    resolveSymbols(syms, lm.l_addr);
    if (!threads.found) checkForThreads(syms, pid);
  }
}

/* ------------------------------ */

static void print_pc(ElfN_Addr addr)
{
  ElfN_Sym *sym;
  Symbols syms;

  findCodeAddress(addr, &sym, &syms);

  if (!sym)
    printf("0x%08lx: ????", (unsigned long) addr);
  else if (sym->st_value < addr)
    printf("0x%08lx: %s + 0x%tx", (unsigned long) addr,
	   &syms->strings[sym->st_name], addr - sym->st_value);
  else
    printf("0x%08lx: %s", (unsigned long) addr, &syms->strings[sym->st_name]);
}

/* ------------------------------ */

#define MAXARGS 6

static int crawl(int pid)
{
  unsigned long pc, fp, nextfp, nargs, i, arg;
  int ret, error_occured = 0;
  DECLARE_REGS_STRUCT(regs);

  errno = 0;

  ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  if (ret != -1) {
    pc = PROGRAM_COUNTER(regs);
    fp = FRAME_POINTER(regs);
  }
  else
    error_occured = 1;

  if (!error_occured) {
    print_pc(pc);
    for ( ; !error_occured && fp; ) {
      nextfp = ptrace(PTRACE_PEEKDATA, pid, NEXT_FRAME_POINTER_ADDR(fp), 0);
      if (nextfp == (unsigned long) -1 && errno) {
        error_occured = 1;
        break;
      }

      nargs = NB_ARGS(fp, nextfp);
      if (nargs > MAXARGS) nargs = MAXARGS;
      if (nargs > 0) {
        fputs(" (", stdout);
        for (i = 1; i <= nargs; i++) {
          arg = ptrace(PTRACE_PEEKDATA, pid, ARG_NMBR(fp,i), 0);
          if (arg == (unsigned long) -1 && errno) {
            error_occured = 1;
            break;
          }
          printf("%lx", arg);
          if (i < nargs) fputs(", ", stdout);
        }
        fputc(')', stdout);
	nargs = NB_ARGS_REMAINING(fp, nextfp, nargs);
        if (!error_occured && nargs > 0) printf(" + %lx\n", nargs);
        else fputc('\n', stdout);
      } else fputc('\n', stdout);

      if (error_occured || !nextfp) break;
      pc = ptrace(PTRACE_PEEKDATA, pid, NEXT_PROGRAM_COUNTER_ADDR(fp), 0);
      if (pc == (unsigned long) -1 && errno) {
        error_occured = 1;
        break;
      }
      fp = nextfp;
      print_pc(pc);
    }
  }

  if (error_occured) perror("crawl");
  else errno = 0;
  return errno;
}

/* ------------------------------ */

static char cmd[128];

static char *cmdLine(int pid)
{
  int fd, len = -1, i;

  sprintf(cmd, "/proc/%d/cmdline", pid);
  if ((fd = open(cmd, O_RDONLY)) >= 0 &&
      (len = read(fd, cmd, sizeof(cmd))) > 0) {
    for (i = 0; i < len; i++) if (!cmd[i]) cmd[i] = ' ';
    for ( ; len > 0 && cmd[len - 1] <= ' '; len--);
    cmd[len] = 0;
    if ((unsigned int) len >= sizeof(cmd) - 4)
      strcpy(&cmd[sizeof(cmd) - 4], "...");
  } else printf("Could not read %s: %s\n", cmd, strerror(errno));
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
  long thePidTmp;
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
    thePidTmp = strtol(*argv, &endptr, 0);
    if (!*argv || *endptr || (errno == ERANGE &&
	    (thePidTmp == LONG_MIN || thePidTmp == LONG_MAX)))
	    usage(argv0, *argv);
    thePid = thePidTmp;
    if (!thePid || thePid == getpid()) {
      fprintf(stderr, "Invalid PID %d\n", thePid);
      continue;
    }

    if (attach(thePid) != 0) {
      fprintf(stderr, "Could not attach to target %d: %s.\n", thePid, strerror(errno));
    } else {
      printf("\n%d: %s\n", thePid, cmdLine(thePid));
      loadSymbols(thePid);
      if (threads.found) {
        for (i = 0; i < threads.npids; i++) {
          if (threads.attached[i]) {
            printf("----- Thread %d -----\n", threads.pids[i]);
            if (crawl(threads.pids[i]) != 1)
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
