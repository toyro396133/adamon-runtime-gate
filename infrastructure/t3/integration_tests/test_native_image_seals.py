"""Actual native image immutability checks; no privileged spawn or VM."""
import ctypes
import fcntl
import os
from pathlib import Path
import subprocess


def test_native_and_python_image_contract_accepts_only_fully_sealed_bytes(tmp_path):
    source=Path(__file__).resolve().parents[1]/'security/native_supervisor.c'
    library=tmp_path/'native.so'
    subprocess.run(['gcc','-shared','-fPIC','-Wall','-Wextra','-Werror',str(source),'-o',str(library)],check=True,capture_output=True)
    lib=ctypes.CDLL(str(library),use_errno=True)
    lib.p4_check_immutable_fd.argtypes=[ctypes.c_int];lib.p4_check_immutable_fd.restype=ctypes.c_int
    fd=os.memfd_create('nonresearch-image',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
    try:
        os.write(fd,b'nonresearch image bytes')
        assert lib.p4_check_immutable_fd(fd)==-1
        fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),getattr(fcntl,'F_SEAL_GROW',4)|getattr(fcntl,'F_SEAL_SHRINK',2))
        assert lib.p4_check_immutable_fd(fd)==-1
        fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),getattr(fcntl,'F_SEAL_WRITE',8)|getattr(fcntl,'F_SEAL_SEAL',1))
        assert lib.p4_check_immutable_fd(fd)==0
    finally:os.close(fd)
    regular=tmp_path/'mutable.bin';regular.write_bytes(b'mutable')
    fd=os.open(regular,os.O_RDONLY)
    try:assert lib.p4_check_immutable_fd(fd)==-1
    finally:os.close(fd)
