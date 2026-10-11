"""Read-only, nonresearch host preparation probe. Never authorizes a campaign."""
from __future__ import annotations
import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import ssl
import sys


def inspect_host():
    checks = {}
    checks['python'] = {'state': 'OBSERVED', 'version': '.'.join(map(str, sys.version_info[:3]))}
    checks['tls'] = {'state': 'OBSERVED', 'version': ssl.OPENSSL_VERSION}
    checks['pidfd_api'] = {'state': 'AVAILABLE' if hasattr(os, 'pidfd_open') else 'MISSING', 'runtime_isolation': 'UNVERIFIED'}
    checks['cgroup_v2'] = {'state': 'AVAILABLE' if Path('/sys/fs/cgroup/cgroup.controllers').is_file() else 'MISSING', 'write_and_kill': 'UNVERIFIED'}
    checks['kvm'] = {'state': 'AVAILABLE' if os.access('/dev/kvm', os.R_OK | os.W_OK) else 'MISSING', 'microvm_isolation': 'UNVERIFIED'}
    checks['disk_capacity'] = {'state': 'OBSERVED', 'free_bytes': shutil.disk_usage('.').free, 'required_free_bytes': 512 * 1024**3}
    checks['cpu_capacity'] = {'state': 'OBSERVED', 'logical_cpus': os.cpu_count(), 'minimum':8}
    try:
        lines = Path('/proc/meminfo').read_text().splitlines()
        total = next(int(line.split()[1])*1024 for line in lines if line.startswith('MemTotal:'))
        checks['memory_capacity'] = {'state':'OBSERVED','total_bytes':total,'minimum_bytes':32*1024**3}
    except (OSError, ValueError, StopIteration):
        checks['memory_capacity'] = {'state':'UNVERIFIED'}
    try:
        crypto = importlib.metadata.version('cryptography')
    except importlib.metadata.PackageNotFoundError:
        crypto = 'MISSING'
    checks['cryptography'] = {'state':'OBSERVED','version':crypto}
    for name in ('clone3_execveat_bootstrap', 'privileged_uid_isolation', 'seccomp_lsm', 'mtls_peer_binding',
                 'runner_registration_legacy_broker', 'job_cancellation_descendants', 'owner_permit_ledger',
                 'private_s3_kms_object_lock', 'conditional_multipart_race', 'reviewer_exact_version_retrieval',
                 'private_source_canary', 'workflow_authority', 'capacity_owner_attestation'):
        checks[name] = {'state':'UNVERIFIED'}
    return {'version':1, 'kind':'NONRESEARCH_READ_ONLY_HOST_PROBE', 'status':'PREFLIGHT_INCOMPLETE',
            'research_executed':False, 'execution_authorized':False, 'checks':checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', action='store_true', required=True)
    parser.parse_args()
    print(json.dumps(inspect_host(), sort_keys=True, indent=2))
    return 2

if __name__ == '__main__':
    raise SystemExit(main())
