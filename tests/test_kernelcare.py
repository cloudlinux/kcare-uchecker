import mock
import uchecker

try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO


LIBCARE_INFO_OUT = '{"pid": 20025, "comm": "sshd" , '\
    '"libc-2.17.so": {"buildid": "f9fafde281e0e0e2af45911ad0fa115b64c2cea8", "patchlvl": 2021021205}, '\
    '"libcrypto.so.1.0.2k": {"buildid": "4cf1939f660008cfa869d8364651f31aacd2c1c4", "patchlvl": 2021012902}}\n'\
    'some error\n'\
    '{"pid": 20026, "comm": "php" , '\
    '"libc-2.17.so": {"buildid": "f9fafde281e0e0e2af45911ad0fa115b64c2ce10", "patchlvl": 2021021205}, '\
    '"libcrypto.so.1.0.2k": {"buildid": "4cf1939f660008cfa869d8364651f31aacd2c1c4", "patchlvl": 2021012902}}'


@mock.patch('uchecker.os.system', return_value=0)
def tests_get_patched_data(mock_system, tmpdir):
    libcare_ctl = tmpdir.join('libcare_ctl')
    with mock.patch('uchecker.LIBCARE_CLIENT', str(libcare_ctl)):
        # Kernelare tools does not exist
        libcare_ctl.ensure(file=0)
        assert uchecker.get_patched_data() == set()
        libcare_ctl.ensure(file=1)
        with mock.patch('uchecker.check_output', return_value='{}'):
            assert uchecker.get_patched_data() == set()
        with mock.patch('uchecker.check_output', return_value='{wrong-format}'):
            assert uchecker.get_patched_data() == set()
        with mock.patch('uchecker.check_output', return_value=LIBCARE_INFO_OUT):
            assert uchecker.get_patched_data() == {
                (20025, '4cf1939f660008cfa869d8364651f31aacd2c1c4'),
                (20025, 'f9fafde281e0e0e2af45911ad0fa115b64c2cea8'),
                (20026, '4cf1939f660008cfa869d8364651f31aacd2c1c4'),
                (20026, 'f9fafde281e0e0e2af45911ad0fa115b64c2ce10')
            }
        with mock.patch('uchecker.check_output', side_effect=IOError('test')):
            assert uchecker.get_patched_data() == set()
        with mock.patch('uchecker.LIBCARE_CLIENT', '/file/that/not/exists/'):
            assert uchecker.get_patched_data() == set()
        with mock.patch('uchecker.os.system', return_value=1):
            assert uchecker.get_patched_data() == set()


def test_is_kcplus_handled():
    with mock.patch('uchecker.urlopen', return_value=StringIO('{"buildid1": "hash", "buildid2" :"hash"}')):
        assert uchecker.is_kcplus_handled("buildid1")
    with mock.patch('uchecker.urlopen', return_value=StringIO('{"buildid1": "hash", "buildid2" :"hash"}')):
        assert not uchecker.is_kcplus_handled("buildid3")


def test_get_dist_data():
    with mock.patch('uchecker.urlopen', return_value=StringIO('{}')):
        assert uchecker.get_dist_data('dist') == {}
    uchecker.get_dist_data.clear()

    with mock.patch('uchecker.urlopen', return_value=StringIO('{"dist": {"lib.so": "hash"}}')):
        assert uchecker.get_dist_data('dist') == {"lib.so": "hash"}
    uchecker.get_dist_data.clear()

    with mock.patch('uchecker.urlopen', return_value=StringIO('{"^dist$": {"lib.so": "hash"}}')):
        assert uchecker.get_dist_data('dist') == {"lib.so": "hash"}
    uchecker.get_dist_data.clear()

    with mock.patch('uchecker.urlopen', return_value=StringIO('{"dist": "ref-dist2"}')):
        assert uchecker.get_dist_data('dist') == {}
    uchecker.get_dist_data.clear()

    with mock.patch('uchecker.urlopen', return_value=StringIO('{"dist": "ref-dist2", "dist2": {"lib.so": "hash"}}')):
        assert uchecker.get_dist_data('dist') == {"lib.so": "hash"}
    uchecker.get_dist_data.clear()


def test_iter_maps():
    # Not existing pid
    assert list(uchecker.iter_maps(-1)) == []

    map_line = '7f5fa46d0000-7f5fa46d1000 rw-p 00007000 103:03 6423990  /usr/lib/zsh/5.9/zsh/system.so'
    with mock.patch('uchecker.open', mock.mock_open(read_data=map_line)):
        assert list(uchecker.iter_maps(1)) == [uchecker.Map(
            addr='7f5fa46d0000-7f5fa46d1000',
            perm='rw-p',
            offset='00007000', dev='103:03', inode='6423990',
            pathname='/usr/lib/zsh/5.9/zsh/system.so', flag=None
        )]


def test_is_valid_file_mmap():
    assert uchecker.is_valid_file_mmap(uchecker.Map(None, None, None, None, None, 'path', None)) is True
    assert uchecker.is_valid_file_mmap(uchecker.Map(None, None, None, None, None, 'anon_inode:test', None)) is False
    assert uchecker.is_valid_file_mmap(uchecker.Map(None, None, None, None, None, '/dev/test', None)) is False


def test_is_up_to_date():
    with mock.patch('uchecker.get_dist_data', return_value={}):
        assert uchecker.is_up_to_date("lib.so", "build-id", "dist") is True
    uchecker.get_dist_data.clear()
    with mock.patch('uchecker.get_dist_data', return_value={"lib.so": "build-id"}):
        assert uchecker.is_up_to_date("lib.so", "build-id", "dist") is True
    uchecker.get_dist_data.clear()
    with mock.patch('uchecker.get_dist_data', return_value={"lib.so": "build-id-old"}):
        assert uchecker.is_up_to_date("lib.so", "build-id", "dist") is True
    uchecker.get_dist_data.clear()
