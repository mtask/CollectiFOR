import hashlib

def get_md5(file_path, chunk_size=8192):
    """
    Calculate MD5 hash of a file.
    """
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            md5.update(chunk)
    return md5.hexdigest()

def get_sha1(file_path, chunk_size=8192):
    """
    Calculate SHA-1 hash of a file.
    """
    sha1 = hashlib.sha1()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha1.update(chunk)
    return sha1.hexdigest()

def get_sha256(file_path, chunk_size=8192):
    """
    Calculate SHA-256 hash of a file.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    return sha256.hexdigest()
