"""Legacy bootstrap cannot substitute for deployment permit/guard checks."""
import pytest
from infrastructure.t3.security.supervisor import deliver_launcher_bootstrap
from infrastructure.t3.security.protocol import Denied

@pytest.mark.parametrize('binding',[
 {'role':'LIFE','subject':'D1_normal','job_id':1},
 {'test':'NONRESEARCH_BOOTSTRAP_ONLY','job_id':1,'role':'LIFE'},
 {'test':'NONRESEARCH_BOOTSTRAP_ONLY','job_id':True},
 {'test':'NONRESEARCH_BOOTSTRAP_ONLY','job_id':0},
 {},
])
def test_legacy_key_not_issued_for_role_or_ambiguous_binding(binding):
    # None capabilities prove rejection precedes peer authentication/key birth.
    with pytest.raises(Denied,match='restricted'):
        deliver_launcher_bootstrap(None,None,binding,None)
