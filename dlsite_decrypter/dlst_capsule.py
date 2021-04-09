from pkg_resources import parse_version
from kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
if parse_version(ks_version) < parse_version('0.7'):
    raise Exception('Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s' % ks_version)

class DlstCapsule(KaitaiStruct):

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        pass

    class CapsuleFooter(KaitaiStruct):

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.check_bits_1 = self._io.read_u2le()
            self.check_bits_2 = self._io.read_u2le()
            self.flags = self._io.read_u4le()
            self.field_1 = self._io.read_u4le()
            self.fileinfo_offset = self._io.read_u4le()
            self.fileinfo_len = self._io.read_u4le()
            self.content_offset = self._io.read_u4le()
            self.content_len = self._io.read_u4le()
            self.field_2 = self._io.read_bytes(16)
            self.encrypted_iv = self._io.read_bytes(16)
            self.field_3 = self._io.read_bytes(32)
            self.serviceinfo_offset = self._io.read_u4le()
            self.serviceinfo_len = self._io.read_u4le()
            self.unknown_buf = self._io.read_bytes(6)
            self.license_separator_len = self._io.read_u1()
            self.license_len = self._io.read_u1()
            self.service_id_buf = self._io.read_bytes(16)
            self.unknown_buf_2 = self._io.read_bytes(16)
            self.len = self._io.read_u4le()

    class CapsuleServiceinfo(KaitaiStruct):

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.check_bits_1 = self._io.read_u2le()
            self.check_bits_2 = self._io.read_u2le()
            self.entry_count = self._io.read_u4le()
            self.entries = [None] * self.entry_count
            for i in range(self.entry_count):
                self.entries[i] = self._root.CapsuleServiceinfoEntry(self._io, self, self._root)

    class CapsuleServiceinfoEntry(KaitaiStruct):

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.len = self._io.read_u4le()
            self.index = self._io.read_u4le()
            self.content = self._io.read_bytes(self.len - 8)

    class CapsuleFileinfo(KaitaiStruct):

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.datatype = self._io.read_bytes(4).decode('ASCII')
            self.len = self._io.read_u4le()
            self.check_bits_1 = self._io.read_u2le()
            self.check_bits_2 = self._io.read_u2le()
            self.field_1 = self._io.read_u4le()
            self.unknown_field_2 = self._io.read_bytes(16)
            self.content_name_offset = self._io.read_u4le()
            self.content_name_len = self._io.read_u4le()
            self.field_2 = self._io.read_u4le()
            self.content_id = self._io.read_u4le()
            self.policy_id = self._io.read_u4le()
            self.unknown_field_3 = self._io.read_u4le()
            self.commodity_id = self._io.read_u8le()
            self.unknown_field_4 = self._io.read_u8le()
            self.flags = self._io.read_u4le()
            self.unknown_field_5 = self._io.read_u4le()
            self.encrypted_key = self._io.read_bytes(16)
            self.unknown_buf = self._io.read_bytes(60)

    @property
    def footer(self):
        if hasattr(self, '_m_footer'):
            if hasattr(self, '_m_footer'):
                return self._m_footer
            return
        _pos = self._io.pos()
        self._io.seek(self._io.size() - 144)
        self._m_footer = self._root.CapsuleFooter(self._io, self, self._root)
        self._io.seek(_pos)
        if hasattr(self, '_m_footer'):
            return self._m_footer

    @property
    def serviceinfo(self):
        if hasattr(self, '_m_serviceinfo'):
            if hasattr(self, '_m_serviceinfo'):
                return self._m_serviceinfo
            return
        _pos = self._io.pos()
        self._io.seek(self.footer.serviceinfo_offset)
        self._m_serviceinfo = self._root.CapsuleServiceinfo(self._io, self, self._root)
        self._io.seek(_pos)
        if hasattr(self, '_m_serviceinfo'):
            return self._m_serviceinfo

    @property
    def encrypted_fileinfo(self):
        if hasattr(self, '_m_encrypted_fileinfo'):
            if hasattr(self, '_m_encrypted_fileinfo'):
                return self._m_encrypted_fileinfo
            return
        _pos = self._io.pos()
        self._io.seek(self.footer.fileinfo_offset)
        self._m_encrypted_fileinfo = self._io.read_bytes(self.footer.fileinfo_len)
        self._io.seek(_pos)
        if hasattr(self, '_m_encrypted_fileinfo'):
            return self._m_encrypted_fileinfo

    @property
    def encrypted_content(self):
        if hasattr(self, '_m_encrypted_content'):
            if hasattr(self, '_m_encrypted_content'):
                return self._m_encrypted_content
            return
        if self.footer.content_len > 0:
            _pos = self._io.pos()
            self._io.seek(self.footer.content_offset)
            self._m_encrypted_content = self._io.read_bytes(self.footer.content_len)
            self._io.seek(_pos)
        if hasattr(self, '_m_encrypted_content'):
            return self._m_encrypted_content