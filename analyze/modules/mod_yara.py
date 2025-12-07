import os
from pathlib import Path
import yara
import magic
import hashlib
import pwd

def _get_file_owner(fp):
    st = os.stat(fp)
    uid = st.st_uid
    return pwd.getpwuid(uid).pw_name

def _detect_file_signature(fp, num_bytes=16):
    # Read first N bytes and convert to hex
    try:
        with open(fp, "rb") as f:
            header = f.read(num_bytes)
        hex_sig = " ".join(f"{b:02X}" for b in header)

        # Use python-magic to get the file type description
        filetype = magic.from_file(fp)

        # Return in the desired format
        return f"{hex_sig};{filetype}"
    except PermissionError as e:
        return ""


def _get_file_data(fpath):
    d = {}
    d['filename'] = os.path.basename(fpath)
    d['filepath'] = fpath
    d['extension'] = os.path.splitext(fpath)[1]
    d['filetype'] = _detect_file_signature(fpath)
    try:
        with open(fpath, 'rb') as f:
            d['md5'] = hashlib.md5(f.read()).hexdigest()
    except PermissionError as e:
        d['md5'] = ''
    d['owner'] = _get_file_owner(fpath)
    return d

def search(rules_dir, target_path):
    file_list = []
    matches = []
    if os.path.isfile(target_path):
        file_list.append(target_path)
    elif os.path.isdir(target_path):
        for f in Path(target_path).rglob("*"):
            f = str(f)
            if os.path.isfile(f):
                externals = _get_file_data(f)
                file_list.append([f, externals])
    for r in Path(rules_dir).rglob("*.yar"):
        rule = yara.compile(str(r), externals={ 'filename': "temp",'filepath': "temp", 'extension': "temp", 'filetype': "temp", 'md5': "temp", 'owner': "temp"})
        matches = matches + _run_yara(rule, file_list)
    return matches

def _run_yara(rule, file_list):
    rule_matches = []
    for f in file_list:
        try:
            match = rule.match(f[0], externals=f[1])
            for item in match:
                match = {'rule': None, 'namespace': None, 'tags': [], 'meta': {}, 'strings': []}
                match['rule'] = item.rule
                match['namespace'] = item.namespace
                match['tags'] = item.tags
                match['meta'] = item.meta
                match['strings'] = str(item.strings)
                match['filepath'] = f[0]
                rule_matches.append(match)
        except yara.Error as e:
            print(repr(e))
    return rule_matches
