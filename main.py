import subprocess, sys, pathlib
from dlsite_decrypter import dlsite_kts
from dlsite_decrypter.dlst_package import DlstPackage, DlstCapsule
import psutil
DLSITE_SERVICE_KEY = bytes.fromhex('B1721A49C6AE503EC6117B8B562AB9BFA56E6A589181F90F45178CFFAD9A8B11')

def resource_path(relative_path):
    try:
        base_path = pathlib.Path(sys._MEIPASS).absolute()
    except Exception:
        base_path = pathlib.Path('.').absolute()

    return str(base_path.joinpath(relative_path))


def main():
    pid = None
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].casefold() == 'DLsiteViewer.exe'.casefold():
            pid = proc.info['pid']

    if pid is None:
        print('process DLsiteViewer.exe not found!')
        return
    if len(sys.argv) == 1:
        print('dlsite-key-dumper PATH_TO_DLST_FILE')
        return
    path = pathlib.Path(sys.argv[1])
    if not path.exists():
        print('input file does not exist!')
        return

    with open(path, 'rb') as (f):
        if dlsite_kts.is_file_package_from_file(f):
            p = DlstPackage.from_file(path)
        else:
            print('not a valid dlst file!')
            return

    dlsite_kts.add_package_svckey(p, DLSITE_SERVICE_KEY)
    p.key = subprocess.run([resource_path('dlsite-key-dumper.exe'), str(pid)], input=p.iv, capture_output=True).stdout[0:16]

    print(p.iv.hex(), p.key.hex())

    outputpath = pathlib.Path(path.parent, path.stem)
    outputpath.mkdir(exist_ok=True, parents=True)
    for s, fn in dlsite_kts.export_package_content(p):
        with open(pathlib.Path(outputpath, fn), 'wb') as (f):
            f.write(s)


if __name__ == '__main__':
    main()