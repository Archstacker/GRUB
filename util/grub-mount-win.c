/* grub-mount.c - FUSE driver for filesystems that GRUB understands */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2008,2009,2010 Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */
#define FUSE_USE_VERSION 26
#include <config.h>
#include <grub/types.h>
#include <grub/emu/misc.h>
#include <grub/util/misc.h>
#include <grub/misc.h>
#include <grub/device.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/fs.h>
#include <grub/env.h>
#include <grub/term.h>
#include <grub/mm.h>
#include <grub/lib/hexdump.h>
#include <grub/crypto.h>
#include <grub/command.h>
#include <grub/zfs/zfs.h>
#include <grub/i18n.h>
#include <grub/osdep/hostfile_windows.h>
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#include "../../dokany/dokan/dokan.h"
#include "../../dokany/dokan/fileinfo.h"
#pragma GCC diagnostic error "-Wstrict-prototypes"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-declarations"
#include <argp.h>
#pragma GCC diagnostic error "-Wmissing-prototypes"
#pragma GCC diagnostic error "-Wmissing-declarations"

#include "progname.h"

#define STRCHRSUB(s, old, new) for(char *p = (s); *p; p++) if(*p == (old)) *p = (new);

static const char *root = NULL;
grub_device_t dev = NULL;
grub_fs_t fs = NULL;
static char **images = NULL;
static char *debug_str = NULL;
static char **fuse_args = NULL;
static int fuse_argc = 0;
static int num_disks = 0;
static int mount_crypt = 0;

static grub_err_t
execute_command (const char *name, int n, char **args)
{
  grub_command_t cmd;

  cmd = grub_command_find (name);
  if (! cmd)
    grub_util_error (_("can't find command `%s'"), name);

  return (cmd->func) (cmd, n, args);
}

/* Translate GRUB error numbers into OS error numbers.  Print any unexpected
   errors.  */
static int
translate_error (void)
{
  int ret;

  switch (grub_errno)
    {
      case GRUB_ERR_NONE:
	ret = 0;
	break;

      case GRUB_ERR_OUT_OF_MEMORY:
	grub_print_error ();
	ret = -ENOMEM;
	break;

      case GRUB_ERR_BAD_FILE_TYPE:
	/* This could also be EISDIR.  Take a guess.  */
	ret = -ENOTDIR;
	break;

      case GRUB_ERR_FILE_NOT_FOUND:
	ret = -ENOENT;
	break;

      case GRUB_ERR_FILE_READ_ERROR:
      case GRUB_ERR_READ_ERROR:
      case GRUB_ERR_IO:
	grub_print_error ();
	ret = -EIO;
	break;

      case GRUB_ERR_SYMLINK_LOOP:
	ret = -ELOOP;
	break;

      default:
	grub_print_error ();
	ret = -EINVAL;
	break;
    }

  /* Any previous errors were handled.  */
  grub_errno = GRUB_ERR_NONE;

  return ret;
}

static int DOKAN_CALLBACK
MirrorCreateFile(
            LPCWSTR                 FileName,
            DWORD                   AccessMode,
            DWORD                   ShareMode,
            DWORD                   CreationDisposition,
            DWORD                   FlagsAndAttributes,
            PDOKAN_FILE_INFO        DokanFileInfo)
{
    char *path;
    grub_file_t file;
    path = grub_util_tchar_to_utf8(FileName);
    STRCHRSUB(path, '\\', '/');
    file = grub_file_open (path);
    DokanFileInfo->Context = *(ULONG*)&file;
    grub_errno = GRUB_ERR_NONE;
    return 0;
}

static int DOKAN_CALLBACK
MirrorOpenDirectory(
            LPCWSTR                 FileName,
            PDOKAN_FILE_INFO        DokanFileInfo)
{
    return 0;
}

static int DOKAN_CALLBACK
MirrorCleanup(
            LPCWSTR                 FileName,
            PDOKAN_FILE_INFO        DokanFileInfo)
{
    if(DokanFileInfo->Context)
    {
        grub_file_close(*(grub_file_t *)&DokanFileInfo->Context);
        DokanFileInfo->Context = 0;
    }
    grub_errno = GRUB_ERR_NONE;
    return 0;
}

static int DOKAN_CALLBACK
MirrorReadFile(
            LPCWSTR             FileName,
            LPVOID              Buffer,
            DWORD               BufferLength,
            LPDWORD             ReadLength,
            LONGLONG            Offset,
            PDOKAN_FILE_INFO    DokanFileInfo)
{
    grub_file_t file = *(grub_file_t *)&(DokanFileInfo->Context);
    grub_ssize_t size;

    if(!file) {
        char *path;
        path = grub_util_tchar_to_utf8(FileName);
        STRCHRSUB(path, '\\', '/');
        file = grub_file_open (path);
        if (! file)
          return translate_error ();
        DokanFileInfo->Context = *(ULONG*)&file;
        grub_errno = GRUB_ERR_NONE;
    }

    if (Offset > file->size)
      return -EINVAL;

    file->offset = Offset;

    size = grub_file_read (file, Buffer, BufferLength);
    if (size < 0)
      return translate_error ();
    else
    {
        *ReadLength = (DWORD)size;
        grub_errno = GRUB_ERR_NONE;
        return 0;
    }
}

/* Context for fuse_getattr.  */
struct fuse_getattr_ctx
{
  char *filename;
  struct grub_dirhook_info file_info;
  int file_exists;
};

/* A hook for iterating directories. */
static int
fuse_getattr_find_file (const char *cur_filename,
			const struct grub_dirhook_info *info, void *data)
{
  struct fuse_getattr_ctx *ctx = data;

  if ((info->case_insensitive ? grub_strcasecmp (cur_filename, ctx->filename)
       : grub_strcmp (cur_filename, ctx->filename)) == 0)
    {
      ctx->file_info = *info;
      ctx->file_exists = 1;
      return 1;
    }
  return 0;
}

static int DOKAN_CALLBACK
MirrorGetFileInformation(
            LPCWSTR                         FileName,
            LPBY_HANDLE_FILE_INFORMATION    HandleFileInformation,
            PDOKAN_FILE_INFO                DokanFileInfo)
{
    char *path;
    char *pathname, *path2;
    struct fuse_getattr_ctx ctx;
    path = grub_util_tchar_to_utf8(FileName);
    STRCHRSUB(path, '\\', '/');
    if (path[0] == '/' && path[1] == 0)
    {
        HandleFileInformation->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        return 0;
    }
    ctx.file_exists = 0;
    pathname = xstrdup (path);
    /* Remove trailing '/'. */
    while (*pathname && pathname[grub_strlen (pathname) - 1] == '/')
      pathname[grub_strlen (pathname) - 1] = 0;

    /* Split into path and filename. */
    ctx.filename = grub_strrchr (pathname, '/');
    if (! ctx.filename)
    {
        path2 = grub_strdup ("/");
        ctx.filename = pathname;
    }
    else
    {
        ctx.filename++;
        path2 = grub_strdup (pathname);
        path2[ctx.filename - pathname] = 0;
    }

    /* It's the whole device. */
    (fs->dir) (dev, path2, fuse_getattr_find_file, &ctx);

    grub_free (path2);
    if (!ctx.file_exists)
    {
        grub_errno = GRUB_ERR_NONE;
        return -ENOENT;
    }
    HandleFileInformation->dwFileAttributes = ctx.file_info.dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
    if (!ctx.file_info.dir)
    {
        grub_file_t file;
        file = grub_file_open (path);
        if (! file && grub_errno == GRUB_ERR_BAD_FILE_TYPE)
        {
            grub_errno = GRUB_ERR_NONE;
            HandleFileInformation->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        }
        else if (! file)
          return translate_error ();
        else
        {
            HandleFileInformation->nFileSizeHigh = (file->size >> 32) & GRUB_UINT_MAX;
            HandleFileInformation->nFileSizeLow = file->size & GRUB_UINT_MAX;
            grub_file_close (file);
        }
    }
    HandleFileInformation->dwFileAttributes |= FILE_ATTRIBUTE_READONLY;
    grub_uint64_t mtime = ctx.file_info.mtimeset
        ? (ctx.file_info.mtime * 10000000ULL +
                    ( 86400ULL * 365 * (1970 - 1601) + 86400ULL * ((1970 - 1601) / 4)
                      - 86400ULL * ((1970 - 1601) / 100) ) * 10000000ULL)
        : 0 ;
    HandleFileInformation->ftCreationTime = HandleFileInformation->ftLastAccessTime =
        HandleFileInformation->ftLastWriteTime = *(FILETIME *)&mtime;
    return 0;
}

struct fuse_readdir_ctx
{
    char* FilePath;
    PFillFindData FillFindData;
    PDOKAN_FILE_INFO DokanFileInfo;
};

static int
MirrorFindFilesFill (const char *filename,
                     const struct grub_dirhook_info *info, void *data)
{
    struct fuse_readdir_ctx *ctx = data;
    WIN32_FIND_DATAW findData;
    wcscpy_s(findData.cFileName, MAX_PATH, grub_util_utf8_to_tchar(filename));
    findData.dwFileAttributes = info->dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
    if (!info->dir)
    {
        grub_file_t file;
        char *tmp;
        tmp = xasprintf ("%s/%s", ctx->FilePath, filename);
        file = grub_file_open (tmp);
        free (tmp);
        /* Symlink to directory.  */
        if (! file && grub_errno == GRUB_ERR_BAD_FILE_TYPE)
        {
            findData.dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        }
        else if (file)
        {
            findData.nFileSizeHigh = (file->size >> 32) & GRUB_UINT_MAX;
            findData.nFileSizeLow = file->size & GRUB_UINT_MAX;
            grub_file_close (file);
        }
    }
    findData.dwFileAttributes |= FILE_ATTRIBUTE_READONLY;
    grub_uint64_t mtime = info->mtimeset
        ? (info->mtime * 10000000ULL +
                    ( 86400ULL * 365 * (1970 - 1601) + 86400ULL * ((1970 - 1601) / 4)
                      - 86400ULL * ((1970 - 1601) / 100) ) * 10000000ULL)
        : 0 ;
    findData.ftCreationTime = findData.ftLastAccessTime =
        findData.ftLastWriteTime = *(FILETIME *)&mtime;
    ctx->FillFindData (&findData,ctx->DokanFileInfo);
    return 0;
}

static int DOKAN_CALLBACK
MirrorFindFiles(
            LPCWSTR             FileName,
            PFillFindData       FillFindData, // function pointer
            PDOKAN_FILE_INFO    DokanFileInfo)
{
    char *path;
    path = grub_util_tchar_to_utf8(FileName);
    STRCHRSUB(path, '\\', '/');

    struct fuse_readdir_ctx ctx = {
        .FilePath = path,
        .FillFindData = FillFindData,
        .DokanFileInfo = DokanFileInfo
    };

    char *pathname;
    pathname = xstrdup (path);

    /* Remove trailing '/'. */
    while (pathname [0] && pathname[1]
                && pathname[grub_strlen (pathname) - 1] == '/')
      pathname[grub_strlen (pathname) - 1] = 0;

    (fs->dir) (dev, pathname, MirrorFindFilesFill, &ctx);
    free (pathname);
    grub_errno = GRUB_ERR_NONE;
    return 0;
}

static grub_err_t
fuse_init (void)
{
    int i;
    int status;
    PDOKAN_OPERATIONS dokanOperations =
        (PDOKAN_OPERATIONS)malloc(sizeof(DOKAN_OPERATIONS));
    if (dokanOperations == NULL) {
        return -1;
    }
    PDOKAN_OPTIONS dokanOptions =
        (PDOKAN_OPTIONS)malloc(sizeof(DOKAN_OPTIONS));
    if (dokanOptions == NULL) {
        free(dokanOperations);
        return -1;
    }
    dokanOptions->Version = DOKAN_VERSION;
    dokanOptions->ThreadCount = 0; // use default

    dokanOptions->MountPoint = grub_util_utf8_to_tchar(images[num_disks - 1]);
    num_disks--;
    dokanOptions->Options |= DOKAN_OPTION_KEEP_ALIVE;
    dokanOptions->Options |= DOKAN_OPTION_ALT_STREAM;
    ZeroMemory(dokanOperations, sizeof(DOKAN_OPERATIONS));

  for (i = 0; i < num_disks; i++)
    {
      char *argv[2];
      char *host_file;
      char *loop_name;
      loop_name = grub_xasprintf ("loop%d", i);
      if (!loop_name)
	grub_util_error ("%s", grub_errmsg);

      host_file = grub_xasprintf ("(host)%s", images[i]);
      if (!host_file)
	grub_util_error ("%s", grub_errmsg);

      argv[0] = loop_name;
      argv[1] = host_file;

      if (execute_command ("loopback", 2, argv))
        grub_util_error (_("`loopback' command fails: %s"), grub_errmsg);

      grub_free (loop_name);
      grub_free (host_file);
    }

  if (mount_crypt)
    {
      char *argv[2] = { xstrdup ("-a"), NULL};
      if (execute_command ("cryptomount", 1, argv))
	  grub_util_error (_("`cryptomount' command fails: %s"),
			   grub_errmsg);
      free (argv[0]);
    }

  grub_lvm_fini ();
  grub_mdraid09_fini ();
  grub_mdraid1x_fini ();
  grub_diskfilter_fini ();
  grub_diskfilter_init ();
  grub_mdraid09_init ();
  grub_mdraid1x_init ();
  grub_lvm_init ();

  dev = grub_device_open (0);
  if (! dev)
    return grub_errno;

  fs = grub_fs_probe (dev);
  if (! fs)
    {
      grub_device_close (dev);
      return grub_errno;
    }

  dokanOperations->CreateFile = MirrorCreateFile;
  dokanOperations->OpenDirectory = MirrorOpenDirectory;
  dokanOperations->Cleanup = MirrorCleanup;
  dokanOperations->ReadFile = MirrorReadFile;
  dokanOperations->GetFileInformation = MirrorGetFileInformation;
  dokanOperations->FindFiles = MirrorFindFiles;

  status = DokanMain(dokanOptions, dokanOperations);
  switch (status) {
      case DOKAN_SUCCESS:
          fprintf(stderr, "Success\n");
          break;
      case DOKAN_ERROR:
          fprintf(stderr, "Error\n");
          break;
      case DOKAN_DRIVE_LETTER_ERROR:
          fprintf(stderr, "Bad Drive letter\n");
          break;
      case DOKAN_DRIVER_INSTALL_ERROR:
          fprintf(stderr, "Can't install driver\n");
          break;
      case DOKAN_START_ERROR:
          fprintf(stderr, "Driver something wrong\n");
          break;
      case DOKAN_MOUNT_ERROR:
          fprintf(stderr, "Can't assign a drive letter\n");
          break;
      case DOKAN_MOUNT_POINT_ERROR:
          fprintf(stderr, "Mount point error\n");
          break;
      default:
          fprintf(stderr, "Unknown error: %d\n", status);
          break;
  }

  free(dokanOptions);
  free(dokanOperations);

  for (i = 0; i < num_disks; i++)
    {
      char *argv[2];
      char *loop_name;

      loop_name = grub_xasprintf ("loop%d", i);
      if (!loop_name)
	grub_util_error ("%s", grub_errmsg);

      argv[0] = xstrdup ("-d");
      argv[1] = loop_name;

      execute_command ("loopback", 2, argv);

      grub_free (argv[0]);
      grub_free (loop_name);
    }

  return grub_errno;
}

static struct argp_option options[] = {  
  {"root",      'r', N_("DEVICE_NAME"), 0, N_("Set root device."),                 2},
  {"debug",     'd', N_("STRING"),           0, N_("Set debug environment variable."),  2},
  {"crypto",   'C', NULL, 0, N_("Mount crypto devices."), 2},
  {"zfs-key",      'K',
   /* TRANSLATORS: "prompt" is a keyword.  */
   N_("FILE|prompt"), 0, N_("Load zfs crypto key."),                 2},
  {"verbose",   'v', NULL, 0, N_("print verbose messages."), 2},
  {0, 0, 0, 0, 0, 0}
};

/* Print the version information.  */
static void
print_version (FILE *stream, struct argp_state *state)
{
  fprintf (stream, "%s (%s) %s\n", program_name, PACKAGE_NAME, PACKAGE_VERSION);
}
void (*argp_program_version_hook) (FILE *, struct argp_state *) = print_version;

static error_t 
argp_parser (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'r':
      root = arg;
      return 0;

    case 'K':
      if (strcmp (arg, "prompt") == 0)
	{
	  char buf[1024];	  
	  grub_printf ("%s", _("Enter ZFS password: "));
	  if (grub_password_get (buf, 1023))
	    {
	      grub_zfs_add_key ((grub_uint8_t *) buf, grub_strlen (buf), 1);
	    }
	}
      else
	{
	  FILE *f;
	  ssize_t real_size;
	  grub_uint8_t buf[1024];
	  f = grub_util_fopen (arg, "rb");
	  if (!f)
	    {
	      printf (_("%s: error:"), program_name);
	      printf (_("cannot open `%s': %s"), arg, strerror (errno));
	      printf ("\n");
	      return 0;
	    }
	  real_size = fread (buf, 1, 1024, f);
	  if (real_size < 0)
	    {
	      printf (_("%s: error:"), program_name);
	      printf (_("cannot read `%s': %s"), arg,
		      strerror (errno));
	      printf ("\n");
	      fclose (f);
	      return 0;
	    }
	  grub_zfs_add_key (buf, real_size, 0);
	  fclose (f);
	}
      return 0;

    case 'C':
      mount_crypt = 1;
      return 0;

    case 'd':
      debug_str = arg;
      return 0;

    case 'v':
      verbosity++;
      return 0;

    case ARGP_KEY_ARG:
      if (arg[0] != '-')
	break;

    default:
      if (!arg)
	return 0;

      fuse_args = xrealloc (fuse_args, (fuse_argc + 1) * sizeof (fuse_args[0]));
      fuse_args[fuse_argc] = xstrdup (arg);
      fuse_argc++;
      return 0;
    }

  images = xrealloc (images, (num_disks + 1) * sizeof (images[0]));
  images[num_disks] = grub_canonicalize_file_name (arg);
  num_disks++;

  return 0;
}

struct argp argp = {
  options, argp_parser, N_("IMAGE1 [IMAGE2 ...] MOUNTPOINT"),
  N_("Debug tool for filesystem driver."), 
  NULL, NULL, NULL
};

int
main (int argc, char *argv[])
{
  const char *default_root;
  char *alloc_root;

  grub_util_host_init (&argc, &argv);

  argp_parse (&argp, argc, argv, 0, 0, 0);
  
  if (num_disks < 2)
    grub_util_error ("%s", _("need an image and mountpoint"));

  /* Initialize all modules. */
  grub_init_all ();

  if (debug_str)
    grub_env_set ("debug", debug_str);

  default_root = (num_disks == 2) ? "loop0" : "md0";
  alloc_root = 0;
  if (root)
    {
      if ((*root >= '0') && (*root <= '9'))
        {
          alloc_root = xmalloc (strlen (default_root) + strlen (root) + 2);

          sprintf (alloc_root, "%s,%s", default_root, root);
          root = alloc_root;
        }
    }
  else
    root = default_root;

  grub_env_set ("root", root);

  if (alloc_root)
    free (alloc_root);

  /* Do it.  */
  fuse_init ();
  if (grub_errno)
    {
      grub_print_error ();
      return 1;
    }

  /* Free resources.  */
  grub_fini_all ();

  return 0;
}
