#!/usr/bin/env python

from __future__ import unicode_literals

""" Detect outdated shared libraries.

Detect and report not up-to-date shared libraries that used by running
processes. Detection based on BuildID comparison and aware of deleted or
replaced files.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

__author__ = 'Rinat Sabitov'
__copyright__ = "Copyright (c) Cloud Linux GmbH & Cloud Linux Software, Inc"
__license__ = "GPLv2"
__maintainer__ = 'Rinat Sabitov'
__email__ = 'rsabitov@cloudlinux.com'
__status__ = 'Beta'
__version__ = '0.1'

import os
import json
import struct
import logging
import subprocess

from collections import namedtuple

ELF64_HEADER = "<16sHHIQQQIHHHHHH"
ELF_PH_HEADER = "<IIQQQQQQ"
ELF_NHDR = "<3I"
PT_NOTE = 4
NT_GNU_BUILD_ID = 3
IGNORED_PATHNAME = ["[heap]", "[stack]", "[vdso]", "[vsyscall]", "[vvar]"]

Vma = namedtuple('Vma', 'offset size start end')
Map = namedtuple('Map', 'addr perm offset dev inode pathname flag')

try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen

LIBCARE_CTL = '/usr/libexec/kcare/libcare-ctl'
USERSPACE_JSON = 'https://gist.githubusercontent.com/histrio/f1532b287f4f6b206ddb8a903d41e423/raw/userspace.json'
KCARE_PLUS_JSON = 'https://patches04.kernelcare.com/userspace-patches.json'
LOGLEVEL = os.environ.get('LOGLEVEL', 'ERROR').upper()
logging.basicConfig(level=LOGLEVEL, format='%(message)s')


def check_output(*args, **kwargs):
    """ Backported implementation for check_output.
    """
    out, err = '', ''
    try:
        p = subprocess.Popen(stdout=subprocess.PIPE, stderr=subprocess.PIPE, *args, **kwargs)
        out, err = p.communicate()
    except OSError as e:
        logging.debug('Subprocess `%s %s` error: (%s) %s', args, kwargs, e, err)
    return out


def _linux_distribution():
    """
    An alternative implementation became necessary because Python
    3.5 deprecated this function, and Python 3.8 removed it altogether.

    Additional parameters like `full_distribution_name` are not implemented.
    """

    uname_raw = check_output(['uname', '-rs'])
    uname_name, _, uname_version = uname_raw.partition(b' ')
    uname = {'id': uname_name.lower(), 'name': uname_name, 'release': uname_version}

    os_release_raw = check_output(['cat', '/etc/os-release'])
    os_release = {}
    for line in os_release_raw.split(b'\n'):
        k, _, v = line.partition(b'=')
        k = k.lower()
        if k in (b'name', ):
            os_release['name'] = v.strip(b'"')
        elif k in (b'version', b'version_id', ):
            os_release['version'] = v
        elif k in (b'version_codename', b'ubuntu_codename', ):
            os_release['codename'] = v
        elif k in (b'pretty_name', ):
            os_release['pretty_name_version_id'] = v.split(b' ')[-1]

    lsb_release_raw = check_output(['lsb_release', '-a'])
    lsb_release = {}
    for line in lsb_release_raw.split('\n'):
        k, _, v = line.partition(':')
        k = k.lower()
        if k in (b'codename', ):
            lsb_release['codename'] = v
        elif k in (b'release', ):
            lsb_release['release'] = v
        elif k in (b'distributor id', ):
            lsb_release['distributor_id'] = v
        elif k in (b'description', ):
            lsb_release['desciption_version_id'] = 'test'

    for dist_file in sorted(check_output(['ls', '/etc']).split(b'\n')):
        if (dist_file.endswith(b'-release') or dist_file.endswith(b'_version')):
            distro_release_raw = check_output(['cat', os.path.join(b'/etc', dist_file)])
            if distro_release_raw:
                break

    distro_release_name, _, distro_release_version = distro_release_raw.partition(b' release ')
    distro_release_version, _, distro_release_codename = distro_release_version.partition(b' ')
    distro_release = {
        'name': distro_release_name,
        'version_id': distro_release_version,
        'codename': distro_release_codename
    }

    name_sources = (
        (os_release, "name"),
        (lsb_release, "distributor_id"),
        (distro_release, "name"),
        (uname, "name")
    )

    codename_sources = (
        (os_release, 'codename'),
        (lsb_release, 'codename'),
        (distro_release, 'codename')
    )

    version_sources = (
        (os_release, 'version_id'),
        (lsb_release, 'release'),
        (distro_release, 'version_id'),
        (os_release, 'pretty_name_version_id'),
        (lsb_release, 'description_version_id'),
        (uname, 'release')
    )

    def first(sources):
        for source, field in sources:
            val = source.get(field)
            if val is not None:
                return val.strip()
        return ''

    return first(name_sources), first(version_sources), first(codename_sources)


def get_dist():
    try:
        from platform import linux_distribution
    except ImportError:
        linux_distribution = _linux_distribution

    name, version, codename = linux_distribution()
    return (name + version).replace(b' ', b'-').lower().decode('utf-8')


def get_patched_data():
    result = set()

    if os.path.isfile(LIBCARE_CTL):
        try:
            output = check_output([LIBCARE_CTL, 'info', '-j'])
            for line in output.splitlines():
                item = json.loads(line)
                for v in item.values():
                    if isinstance(v, dict) and 'buildid' in v:
                        result.add((item['pid'], v['buildid']))
        except Exception as e:
            logging.debug(e)

    return result


DIST = get_dist()
DATA = json.load(urlopen(USERSPACE_JSON)).get(DIST, {})

# Handle references
if 'ref-' in DATA:
    DIST = DATA[4:]
    DATA = json.load(urlopen(USERSPACE_JSON)).get(DIST) or {}


KCPLUS_DATA = json.load(urlopen(KCARE_PLUS_JSON))
PATCHED_DATA = get_patched_data()


class NotAnELFException(Exception):
    pass


class BuildIDParsingException(Exception):
    pass


def get_build_id(fileobj):

    try:
        header = fileobj.read(struct.calcsize(ELF64_HEADER))
        hdr = struct.unpack(ELF64_HEADER, header)
    except struct.error as err:
        # Cant't read ELF header
        raise NotAnELFException("Can't read header: {0}".format(err))

    (e_ident, e_type, e_machine, e_version, e_entry, e_phoff,
     e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
     e_shentsize, e_shnum, e_shstrndx) = hdr

    # Not an ELF file
    if not e_ident.startswith(b'\x7fELF\x02\x01'):
        raise NotAnELFException("Wrong header")

    # No program headers
    if not e_phoff:
        raise BuildIDParsingException("Program headers not found.")

    logging.debug("e_phoff: %d, e_phnum: %d, e_phentsize: %d", e_phoff, e_phnum, e_phentsize)

    fileobj.seek(e_phoff)
    for idx in range(e_phnum):
        ph = fileobj.read(e_phentsize)
        (p_type, p_flags, p_offset, p_vaddr, p_paddr,
         p_filesz, p_memsz, p_align) = struct.unpack(ELF_PH_HEADER, ph)
        logging.debug("p_idx: %d, p_type: %d", idx, p_type)
        if p_type == PT_NOTE:
            logging.debug("p_offset: %d, p_filesz: %d", p_offset, p_filesz)
            p_end = p_offset + p_filesz
            fileobj.seek(p_offset)
            n_type = None
            while n_type != NT_GNU_BUILD_ID and fileobj.tell() <= p_end:
                nhdr = fileobj.read(struct.calcsize(ELF_NHDR))
                n_namesz, n_descsz, n_type = struct.unpack(ELF_NHDR, nhdr)

                # 4-byte align
                if n_namesz % 4:
                    n_namesz = ((n_namesz // 4) + 1) * 4
                if n_descsz % 4:
                    n_descsz = ((n_descsz // 4) + 1) * 4

                logging.debug("n_type: %d, n_namesz: %d, n_descsz: %d)",
                              n_type, n_namesz, n_descsz)
                fileobj.read(n_namesz)
                desc = struct.unpack("<{0}B".format(n_descsz), fileobj.read(n_descsz))
            if n_type is not None:
                return ''.join('{:02x}'.format(x) for x in desc)
    # Nothing was found
    raise BuildIDParsingException("Program header PT_NOTE with NT_GNU_BUILD_ID was not found.")


def iter_maps(pid):
    try:
        with open('/proc/{:d}/maps'.format(pid), 'r') as mapfd:
            for line in mapfd:
                data = (line.split() + [None, None])[:7]
                yield Map(*data)
    except IOError as err:
        # Most cases of IOErrors is a lack of maps due to process exit
        logging.debug("Iter via `%d` map error: %s", pid, err)


def get_vmas(pid, inode):
    result = []
    for mmap in iter_maps(pid):
        if mmap.inode == inode:
            start, _, end = mmap.addr.partition('-')
            offset, start, end = map(lambda x: int(x, 16), [mmap.offset, start, end])
            rng = Vma(offset, end - start, start, end)
            result.append(rng)
    return result


def is_valid_file_mmap(mmap):
    return mmap.pathname \
        and mmap.pathname not in IGNORED_PATHNAME \
        and not mmap.pathname.startswith('anon_inode:') \
        and not mmap.pathname.startswith('/dev/')


def get_process_files(pid):
    result = set()
    for mmap in iter_maps(pid):
        if is_valid_file_mmap(mmap):
            pathname, _, _ = mmap.pathname.partition(';')
            result.add((pathname, mmap.inode))
    return result


class FileMMapped(object):

    def __init__(self, pid, inode):
        self.fileobj = open('/proc/{:d}/mem'.format(pid), 'rb')
        self.vmas = get_vmas(pid, inode)
        self.pos = 0
        self.fileobj.seek(self._get_vma(0).start)

    def _get_vma(self, offset):
        for rng in self.vmas:
            if rng.offset <= offset < rng.offset + rng.size:
                return rng
        raise ValueError("Offset {0} is not in ranges {1}".format(offset, self.vmas))

    def tell(self):
        return self.pos

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.fileobj.close()

    def close(self):
        self.fileobj.close()

    def seek(self, offset, whence=0):
        rng = self._get_vma(offset)
        addr = rng.start + (offset - rng.offset)
        self.fileobj.seek(addr, whence)
        self.pos = offset

    def read(self, size):
        result = self.fileobj.read(size)
        self.pos += len(result)
        return result


open_mmapped = FileMMapped


def get_comm(pid):
    comm_filename = '/proc/{:d}/comm'.format(pid)
    with open(comm_filename, 'r') as fd:
        return fd.read().strip()


def iter_pids():
    for pid in os.listdir('/proc/'):
        try:
            yield int(pid)
        except ValueError:
            pass


def iter_proc_map():
    for pid in iter_pids():
        for pathname, inode in get_process_files(pid):
            yield pid, inode, pathname


def get_fileobj(pid, inode, pathname):
    logging.debug("path: %s", pathname)
    # If mapped file exists and has the same inode
    if os.path.isfile(pathname) and os.stat(pathname).st_ino == int(inode):
        fileobj = open(pathname, 'rb')
    # If file exists only as a mapped to the memory
    else:
        fileobj = open_mmapped(pid, inode)
        logging.warning("Library `%s` was gathered from memory.", pathname)
    return fileobj


def iter_proc_lib():
    cache = {}
    for pid, inode, pathname in iter_proc_map():
        if inode not in cache:
            try:
                with get_fileobj(pid, inode, pathname) as fileobj:
                    cache[inode] = get_build_id(fileobj)
            except (NotAnELFException, BuildIDParsingException) as err:
                logging.info("Cat't read buildID from {0}: {1}".format(pathname, err))
                cache[inode] = None
            except Exception as err:
                logging.error("Cat't read buildID from {0}: {1}".format(pathname, err))
                cache[inode] = None
        build_id = cache[inode]
        yield pid, os.path.basename(pathname), build_id


def is_kcplus_handled(build_id):
    return build_id in KCPLUS_DATA


def is_up_to_date(libname, build_id):
    subset = DATA.get(libname, {})
    if not subset:
        logging.warning('No data for %s/%s.', DIST, libname)
    return not subset or build_id in subset


def main():
    failed = False
    logging.info("Distro detected: %s", DIST)
    for pid, libname, build_id in iter_proc_lib():
        comm = get_comm(pid)
        logging.info("For %s[%s] `%s` was found with buid id = %s",
                     comm, pid, libname, build_id)
        if build_id and (pid, build_id) not in PATCHED_DATA \
           and not is_up_to_date(libname, build_id):
            failed = True
            logging.error(
                "[%s] Process %s[%d] linked to the `%s` that is not up to date.",
                "*" if is_kcplus_handled(build_id) else " ",
                comm, pid, libname)

    if not failed:
        print("Everything is OK.")
    else:
        print("\nYou may want to update libraries above and restart "
              "corresponding processes.\n\n KernelCare+ allows to resolve "
              "such issues with no process downtime. To find out more, please,"
              " visit https://lp.kernelcare.com/kernelcare-early-access?")

    return 0 if not failed else 1


if __name__ == '__main__':
    exit(main())
