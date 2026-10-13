import unittest
from infrastructure.t3.security.github_rest import GitHubApi, IdentityUnavailable, OwnerAuthenticatedTransport

SHA='a'*40
BLOB='b'*40
PATH='.github/workflows/gen06-t3-approved.yml@refs/heads/main'
class Tests(unittest.TestCase):
    def setUp(self):
        self.data={
         '/repos/toyro396133/adamon-runtime-gate/actions/runs/22/attempts/2': dict(id=22,run_attempt=2,event='workflow_dispatch',status='in_progress',repository={'full_name':'toyro396133/adamon-runtime-gate','id':99},head_sha=SHA,path=PATH,head_branch='main'),
         '/repos/toyro396133/adamon-runtime-gate/contents/.github/workflows/gen06-t3-approved.yml?ref='+SHA: dict(type='file',sha=BLOB),
         '/repos/toyro396133/adamon-runtime-gate/actions/runs/22/attempts/2/jobs?per_page=100&page=1': dict(total_count=1,jobs=[dict(id=33,run_id=22,run_attempt=2,runner_id=44,status='in_progress',check_run_url='https://api.github.com/repos/toyro396133/adamon-runtime-gate/check-runs/55')])}
        self.client=GitHubApi('toyro396133/adamon-runtime-gate',get_json=lambda p:self.data[p])
    def test_recorded_shape_normalization(self):
        r=self.client.get_run(22,2); j=self.client.list_jobs(22,2)
        self.assertEqual((r['workflow_ref'],r['workflow_sha'],r['run_id']),('toyro396133/adamon-runtime-gate/'+PATH,SHA,22))
        self.assertEqual(j,[dict(job_id=33,check_run_id=55,run_id=22,run_attempt=2,runner_id=44,status='in_progress')])
    def test_attempt_endpoint_without_redundant_attempt_field(self):
        del self.data[next(k for k in self.data if '/jobs?' in k)]['jobs'][0]['run_attempt']
        self.assertEqual(self.client.list_jobs(22,2)[0]['run_attempt'],2)
    def test_rest_path_without_context_ref_suffix(self):
        self.data[next(k for k in self.data if '/actions/runs/' in k and '/jobs?' not in k)]['path']=PATH.split('@')[0]
        self.assertEqual(self.client.get_run(22,2)['workflow_ref'],'toyro396133/adamon-runtime-gate/'+PATH)
    def test_no_fabricated_workflow_sha(self):
        self.data[next(k for k in self.data if '/contents/' in k)]={'type':'file','sha':'invalid'}
        with self.assertRaises(IdentityUnavailable):self.client.get_run(22,2)
    def test_reject_non_dispatch_attempt(self):
        self.data[next(k for k in self.data if '/actions/runs/' in k and '/jobs?' not in k)]['event']='push'
        with self.assertRaises(IdentityUnavailable):self.client.get_run(22,2)
    def test_wrong_run_identity(self):
        self.data[next(k for k in self.data if '/actions/runs/' in k and '/jobs?' not in k)]['id']=23
        with self.assertRaises(IdentityUnavailable):self.client.get_run(22,2)
    def test_missing_or_duplicate_jobs(self):
        self.data[next(k for k in self.data if '/jobs?' in k)]['total_count']=101
        with self.assertRaises(IdentityUnavailable):self.client.list_jobs(22,2)
    def test_attempt_or_boolean_spoof(self):
        for k in ('run_attempt','runner_id'):
            self.setUp(); self.data[next(x for x in self.data if '/jobs?' in x)]['jobs'][0][k]=True
            with self.assertRaises(IdentityUnavailable):self.client.list_jobs(22,2)
    def test_relative_routes_only(self):
        t=OwnerAuthenticatedTransport(token_provider=lambda:'synthetic')
        for route in ('https://example.test','/repos/o/r/actions/jobs/3','/repos/o/r/contents/../../secrets'):
            with self.assertRaises(IdentityUnavailable):t(route)

if __name__=='__main__':unittest.main()
