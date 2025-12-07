import logging
import os
import tarfile

def decompress(src_tar):
    """
    Decompress a .tar.gz file into a directory next to it.
    Returns path to the extracted directory.
    """

    if not os.path.isfile(src_tar):
        raise FileNotFoundError(f"Tar archive not found: {src_tar}")

    # Directory where the tar.gz is located
    base_dir = os.path.dirname(os.path.abspath(src_tar))

    # Directory name = tar filename without .tar.gz
    filename = os.path.basename(src_tar)
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

    with tarfile.open(src_tar, "r:gz") as tar:
        safe_extract(tar, out_dir)

    logging.info(f"Tar decompressed to: {out_dir}")
    return os.path.join(out_dir,os.listdir(out_dir)[0])
