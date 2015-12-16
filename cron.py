from glob import glob
import os
import subprocess

from settings import DATA_DIR

garbage_storages = glob(os.path.join(DATA_DIR, "_**"))
garbage_files =  list(set(glob(os.path.join(DATA_DIR, "_**/_**"))) -
                      set(glob(os.path.join(DATA_DIR, "**/_**"))))

garbages = garbage_files + garbage_storages

for path in garbages:
    subprocess.check_call(['srm', '-r', path])