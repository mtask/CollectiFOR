import logging
import os
import tarfile

def decompress(src_path):
    """
    Decompress a .tar.gz file into a directory next to it.
    Returns path to the extracted directory.
    If path is already extracted collection path return src_path
    """

    if os.path.isdir(src_path) and os.path.isdir(os.path.join(src_path, "files_and_dirs")):
        return src_path
    if not os.path.isfile(src_path):
        raise FileNotFoundError(f"Tar archive not found: {src_path}")

    # Directory where the tar.gz is located
    base_dir = os.path.dirname(os.path.abspath(src_path))

    # Directory name = tar filename without .tar.gz
    filename = os.path.basename(src_path)
    if filename.endswith(".tar.gz"):
        out_dir = os.path.join(base_dir, filename[:-7])
    else:
        # fallback for .tgz
        out_dir = os.path.join(base_dir, os.path.splitext(filename)[0])

    if os.path.isdir(out_dir):
        logging.info(f"Tar already decompressed to: {out_dir}")
        return os.path.join(out_dir,os.listdir(out_dir)[0])

    os.makedirs(out_dir, exist_ok=True)

    def is_within_directory(directory, target):
        abs_directory = os.path.abspath(directory)
        abs_target = os.path.abspath(target)
        return os.path.commonpath([abs_directory, abs_target]) == abs_directory

    def safe_extract(tar, path="."):
        for member in tar.getmembers():
            target = os.path.join(path, member.name)
            if not is_within_directory(path, target):
                raise Exception(f"Blocked unsafe path in tar: {member.name}")
        tar.extractall(path)

    logging.info(f"Extracting collection {src_path} to {out_dir}")
    with tarfile.open(src_path, "r:gz") as tar:
        safe_extract(tar, out_dir)

    logging.info(f"Tar decompressed to: {out_dir}")
    return os.path.join(out_dir,os.listdir(out_dir)[0])
