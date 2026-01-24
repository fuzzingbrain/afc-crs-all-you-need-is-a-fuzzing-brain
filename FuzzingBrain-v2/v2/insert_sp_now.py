#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/ze/CRS/afc-crs-all-you-need-is-a-fuzzing-brain/FuzzingBrain-v2/v2')

from fuzzingbrain.db import MongoDB, RepositoryManager
from fuzzingbrain.core.models import SuspiciousPoint, SPStatus

db = MongoDB.connect()
repos = RepositoryManager(db)

sp1 = SuspiciousPoint(
    task_id='48a64b24',
    function_name='EmitCIEBasedDEF',
    description='Null pointer dereference cmsps2.c:795-796',
    vuln_type='null-pointer-dereference',
    score=0.95,
    is_important=True,
    status=SPStatus.PENDING_VERIFY.value,
    sources=[{'harness_name': 'cms_postscript_fuzzer', 'sanitizer': 'address'}],
    pov_guidance='Target cmsps2.c:795-796',
)

sp2 = SuspiciousPoint(
    task_id='48a64b24',
    function_name='IsProperColorSpace',
    description='Buffer over-read cmsxform.c:1073-1074',
    vuln_type='buffer-over-read',
    score=0.90,
    is_important=True,
    status=SPStatus.PENDING_VERIFY.value,
    sources=[{'harness_name': 'cms_virtual_profile_fuzzer', 'sanitizer': 'address'}],
    pov_guidance='Target cmsxform.c:1073-1074',
)

repos.suspicious_points.insert(sp1)
print(f'SP1: {sp1.suspicious_point_id}')
repos.suspicious_points.insert(sp2)
print(f'SP2: {sp2.suspicious_point_id}')
print('DONE!')
