import mock
import uchecker


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


def test_is_kcplus_handled():
    with mock.patch('uchecker.KCPLUS_DATA', set(['buildid1', 'buildid2'])):
        assert uchecker.is_kcplus_handled("buildid1")
        assert not uchecker.is_kcplus_handled("buildid3")
