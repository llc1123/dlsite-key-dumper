from dlsite_decrypter.dlst_capsule import DlstCapsule
from dlsite_decrypter.dlst_package import DlstPackage
from dlsite_decrypter import crypto_ops
import os, struct

def _decrypt_fileinfo(buf, svckey, iv):
    fileinfo_buf = crypto_ops.decrypt_cbc_cts(svckey, iv, buf)
    return DlstCapsule.CapsuleFileinfo.from_bytes(fileinfo_buf)


def add_capsule_svckey(c, svckey):
    iv = crypto_ops.decrypt_cbc_ecb(svckey, c.footer.encrypted_iv)
    c.iv = iv
    fileinfo = _decrypt_fileinfo(c.encrypted_fileinfo, svckey, iv)
    c.fileinfo = fileinfo


def add_package_svckey(p, svckey):
    iv = crypto_ops.decrypt_cbc_ecb(svckey, p.package_capsule.footer.encrypted_iv)
    p.iv = iv
    fileinfo = _decrypt_fileinfo(p.package_capsule.encrypted_fileinfo, svckey, iv)
    p.fileinfo = fileinfo


def add_content_key(c, contentkey):
    key = crypto_ops.decrypt_cbc_ecb(contentkey, c.fileinfo.encrypted_key)
    c.key = key


def parse_standalone_capsule(filename, svckey=None, contentkey=None):
    c = DlstCapsule.from_file(filename)
    if svckey is not None:
        add_capsule_svckey(c, svckey)
        if contentkey is not None:
            add_content_key(c, contentkey)
    return c


def parse_package(filename, svckey=None, contentkey=None):
    p = DlstPackage.from_file(filename)
    if svckey is not None:
        add_package_svckey(p, svckey)
        if contentkey is not None:
            add_content_key(p, contentkey)
    return p


def export_capsule_content(capsule):
    return crypto_ops.decrypt_file_from_bytes(capsule.encrypted_content, capsule.key, capsule.iv)


def export_package_content(package):
    for s in package.package_storage:
        if s.filename[:-1] != 'index.bin':
            yield (
             crypto_ops.decrypt_file_from_bytes(s.encrypted_content, package.key, package.iv), s.filename[:-1])


def is_file_package_from_file(fobj):
    fobj.seek(-4, os.SEEK_END)
    footer_len = struct.unpack('<I', fobj.read())[0]
    return _check_package_by_footer_size(footer_len)


def is_file_package_from_bytes(buf):
    footer_len = struct.unpack('<I', buf[-4:])[0]
    return _check_package_by_footer_size(footer_len)


def _check_package_by_footer_size(footer_len):
    if footer_len == 60:
        return True
    if footer_len == 144:
        return False
    raise RuntimeError('unrecognised footer size %d' % footer_len)