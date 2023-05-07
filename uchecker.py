#!/usr/bin/env python

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
import re
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
NT_GO_BUILD_ID = 4
IGNORED_PATHNAME = ["[heap]", "[stack]", "[vdso]", "[vsyscall]", "[vvar]"]

Vma = namedtuple('Vma', 'offset size start end')
Map = namedtuple('Map', 'addr perm offset dev inode pathname flag')

try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen

LIBCARE_CLIENT = '/usr/libexec/kcare/libcare-client'
USERSPACE_JSON = 'https://gist.githubusercontent.com/histrio/f1532b287f4f6b206ddb8a903d41e423/raw/userspace.json'
KCARE_PLUS_JSON = 'https://patches.kernelcare.com/userspace-patches.json'
LOGLEVEL = os.environ.get('LOGLEVEL', 'ERROR').upper()
logging.basicConfig(level=LOGLEVEL, format='%(message)s')


def normalize(data, encoding='utf-8'):
    if type(data) is type(''):
        return data
    elif type(data) is type(b''):
        return data.decode(encoding)
    else:
        return data.encode(encoding)


def check_output(*args, **kwargs):
    """ Backported implementation for check_output.
    """
    out = ''
    try:
        p = subprocess.Popen(stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             *args, **kwargs)
        out, err = p.communicate()
        if err or p.returncode != 0:
            raise OSError("{0} ({1})".format(err, p.returncode))
    except OSError as e:
        logging.debug('Subprocess `%s %s` error: %s',
                      args, kwargs, e)
    return normalize(out)


def _linux_distribution(*args, **kwargs):
    """
    An alternative implementation became necessary because Python
    3.5 deprecated this function, and Python 3.8 removed it altogether.

    Additional parameters like `full_distribution_name` are not implemented.
    """

    uname_raw = check_output(['uname', '-rs'])
    uname_name, _, uname_version = uname_raw.partition(' ')
    uname = {'id': uname_name.lower(), 'name': uname_name, 'release': uname_version}

    os_release_raw = check_output(['cat', '/etc/os-release'])
    os_release = {}
    for line in os_release_raw.split('\n'):
        k, _, v = line.partition('=')
        k = k.lower()
        if k in ('name', ):
            os_release['name'] = v.strip('"')
        elif k in ('version', 'version_id', ):
            os_release['version'] = v
        elif k in ('version_codename', 'ubuntu_codename', ):
            os_release['codename'] = v
        elif k in ('pretty_name', ):
            os_release['pretty_name_version_id'] = v.split(' ')[-1]

    lsb_release_raw = check_output(['lsb_release', '-a'])
    lsb_release = {}
    for line in lsb_release_raw.split('\n'):
        k, _, v = line.partition(':')
        k = k.lower()
        if k in ('codename', ):
            lsb_release['codename'] = v
        elif k in ('release', ):
            lsb_release['release'] = v
        elif k in ('distributor id', ):
            lsb_release['distributor_id'] = v
        elif k in ('description', ):
            lsb_release['desciption_version_id'] = 'test'

    for dist_file in sorted(check_output(['ls', '/etc']).split('\n')):
        if (dist_file.endswith('-release') or dist_file.endswith('_version')):
            distro_release_raw = check_output(['cat', os.path.join('/etc', dist_file)])
            if distro_release_raw:
                break

    distro_release_name, _, distro_release_version = distro_release_raw.partition(' release ')
    distro_release_version, _, distro_release_codename = distro_release_version.partition(' ')
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
        from platform import linux_distribution, _supported_dists
        supported_dists = _supported_dists + ('arch', 'system')
    except ImportError:
        linux_distribution = _linux_distribution
        supported_dists = None

    name, version, codename = linux_distribution(supported_dists=supported_dists)
    return (name + version).replace(' ', '-').lower()


def get_patched_data():
    result = set()

    if not os.path.isfile(LIBCARE_CLIENT):
        logging.debug("Libcare tools are not found.")
        return result

    if os.system('service libcare status > /dev/null 2>&1') != 0:
        logging.debug("Libcare service is not running.")
        return result

    try:
        std_out = check_output([LIBCARE_CLIENT, 'info', '-j'])
        for line in std_out.splitlines():
            try:
                item = json.loads(line)
                for v in item.values():
                    if isinstance(v, dict) and 'buildid' in v:
                        result.add((item['pid'], v['buildid']))
            except ValueError as e:
                logging.debug("Can't parse `%s`: %s", line, e)

    except Exception as e:
        logging.debug("Can't read libcare info: %s", e)

    return result


def cache_dist(clbl):
    data = {}

    def wrapper(dist):
        if dist not in data:
            data[dist] = clbl(dist)
        return data[dist]

    wrapper.clear = data.clear
    return wrapper


@cache_dist
def get_dist_data(dist):
    userspace_data = json.load(urlopen(USERSPACE_JSON))
    for dist_re, dist_data in userspace_data.items():
        if re.match(dist_re, dist):
            logging.debug("Distro `%s` was matched by `%s`", dist, dist_re)

            # Handle references
            if 'ref-' in dist_data:
                logging.debug("Distro reference detected: `%s`", dist_data)
                dist_data = userspace_data.get(dist_data[4:]) or {}

            return dist_data
    return {}


class NotAnELFException(Exception):
    pass


class BuildIDParsingException(Exception):
    pass


def get_build_id(fileobj):

    try:
        header = fileobj.read(struct.calcsize(ELF64_HEADER))
        hdr = struct.unpack(ELF64_HEADER, header)
    except struct.error as err:
        # Can't read ELF header
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
            while n_type not in (NT_GNU_BUILD_ID, NT_GO_BUILD_ID) and fileobj.tell() <= p_end:
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
                return ''.join('{0:02x}'.format(x) for x in desc)
    # Nothing was found
    raise BuildIDParsingException("Program header PT_NOTE with NT_GNU_BUILD_ID was not found.")


def iter_maps(pid):
    try:
        with open('/proc/{0:d}/maps'.format(pid), 'r') as mapfd:
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
        self.fileobj = open('/proc/{0:d}/mem'.format(pid), 'rb')
        self.vmas = get_vmas(pid, inode)
        self.pos = 0
        self.fileobj.seek(self._get_vma(0).start)

    def _get_vma(self, offset):
        for rng in self.vmas:
            if rng.offset <= offset < rng.offset + rng.size:
                return rng
        raise IOError("Offset {0} is not in ranges {1}".format(offset, self.vmas))

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
    comm_filename = '/proc/{0:d}/comm'.format(pid)
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
            except (NotAnELFException, BuildIDParsingException, IOError) as err:
                logging.info("Can't read buildID from {0}: {1}".format(pathname, repr(err)))
                cache[inode] = None
            except Exception as err:
                logging.error("Can't read buildID from {0}: {1}".format(pathname, repr(err)))
                cache[inode] = None
        build_id = cache[inode]
        yield pid, os.path.basename(pathname), build_id


def is_kcplus_handled(build_id):
    data = set(json.load(urlopen(KCARE_PLUS_JSON)).keys())
    return build_id in data


def is_up_to_date(libname, build_id, dist):
    subset = get_dist_data(dist).get(libname, {})
    if not subset:
        logging.warning('No data for %s/%s.', dist, libname)
    return (not subset) or (build_id in subset)


def main():
    failed = False
    dist = get_dist()
    logging.info("Distro detected: %s", dist)

    if not get_dist_data(dist):
        logging.error("Distro `%s` is not supported", dist)
        exit(1)

    for pid, libname, build_id in iter_proc_lib():
        comm = get_comm(pid)
        logging.info("For %s[%s] `%s` was found with buid id = %s",
                     comm, pid, libname, build_id)
        if build_id and (pid, build_id) not in get_patched_data() \
           and not is_up_to_date(libname, build_id, dist):
            failed = True
            logging.error(
                "[%s] Process %s[%d] linked to the `%s` that is not up to date.",
                "*" if is_kcplus_handled(build_id) else " ",
                comm, pid, libname)

    if not failed:
        print("It looks OK. We didn't find any outdated libraries.")
    else:
        print("\nYou may want to update libraries above and restart "
              "corresponding processes.\n\n KernelCare+ allows to resolve "
              "such issues with no process downtime. To find out more, please,"
              " visit https://tuxcare.com/live-patching-services/librarycare/")

    return 0 if not failed else 1


if __name__ == '__main__':
    exit(main())
