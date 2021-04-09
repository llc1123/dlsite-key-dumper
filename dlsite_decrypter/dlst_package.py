from pkg_resources import parse_version
from kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO

if parse_version(ks_version) < parse_version("0.7"):
    raise Exception(
        "Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s"
        % ks_version
    )
from dlsite_decrypter.dlst_capsule import DlstCapsule


class DlstPackage(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.package_header = self._root.DlstPackageHeader(self._io, self, self._root)

    class DlstPackageHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.len = self._io.read_u4le()
            self.unknown_field = self._io.read_bytes(16)
            self.content = self._io.read_bytes(self.len - 20).decode("UTF-16")

    class DlstPackageFooter(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.ensure_fixed_contents(b"DNBF")
            self.field_1 = self._io.read_u4le()
            self.field_2 = self._io.read_u4le()
            self.storage_offset = self._io.read_u4le()
            self.file_count = self._io.read_u4le()
            self.field_5 = self._io.read_bytes(28)
            self.capsule_offset = self._io.read_u4le()
            self.len = self._io.read_u4le()

    class DlstStorage(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.ensure_fixed_contents(b"DNBA")
            self.check_bits_1 = self._io.read_u2le()
            self.check_bits_2 = self._io.read_u2le()
            self.bool_1 = self._io.read_u4le()
            self.field_2 = self._io.read_u4le()
            self.field_3 = self._io.read_bytes(8)
            self.content_len = self._io.read_u4le()
            self.field_4 = self._io.read_u4le()
            self.filename_len = self._io.read_u2le()
            self.unknown_segment_len = self._io.read_u2le()
            self.filename = self._io.read_bytes(self.filename_len * 2).decode(
                "UTF-16-LE"
            )
            self.unknown_segment = self._io.read_bytes(self.unknown_segment_len)
            self.encrypted_content = self._io.read_bytes(self.content_len)

    @property
    def package_footer(self):
        if hasattr(self, "_m_package_footer"):
            if hasattr(self, "_m_package_footer"):
                return self._m_package_footer
            return
        _pos = self._io.pos()
        self._io.seek(self._io.size() - 60)
        self._m_package_footer = self._root.DlstPackageFooter(
            self._io, self, self._root
        )
        self._io.seek(_pos)
        if hasattr(self, "_m_package_footer"):
            return self._m_package_footer

    @property
    def package_storage(self):
        if hasattr(self, "_m_package_storage"):
            if hasattr(self, "_m_package_storage"):
                return self._m_package_storage
            return
        _pos = self._io.pos()
        self._io.seek(self.package_footer.storage_offset)
        self._m_package_storage = [None] * self.package_footer.file_count
        for i in range(self.package_footer.file_count):
            self._m_package_storage[i] = self._root.DlstStorage(
                self._io, self, self._root
            )

        self._io.seek(_pos)
        if hasattr(self, "_m_package_storage"):
            return self._m_package_storage

    @property
    def package_capsule_len(self):
        if hasattr(self, "_m_package_capsule_len"):
            if hasattr(self, "_m_package_capsule_len"):
                return self._m_package_capsule_len
            return
        _pos = self._io.pos()
        self._io.seek(self.package_footer.capsule_offset)
        self._m_package_capsule_len = self._io.read_u8le()
        self._io.seek(_pos)
        if hasattr(self, "_m_package_capsule_len"):
            return self._m_package_capsule_len

    @property
    def package_capsule(self):
        if hasattr(self, "_m_package_capsule"):
            if hasattr(self, "_m_package_capsule"):
                return self._m_package_capsule
            return
        _pos = self._io.pos()
        self._io.seek(self.package_footer.capsule_offset + 8)
        self._raw__m_package_capsule = self._io.read_bytes(self.package_capsule_len)
        io = KaitaiStream(BytesIO(self._raw__m_package_capsule))
        self._m_package_capsule = DlstCapsule(io)
        self._io.seek(_pos)
        if hasattr(self, "_m_package_capsule"):
            return self._m_package_capsule
