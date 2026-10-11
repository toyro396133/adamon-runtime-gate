"""Read-only GitHub Actions attempt/Job identity adapter for trusted supervisor.

Uses only fixed GitHub REST API endpoints; no request-selected URL, headers or
runner-supplied job identity. Not an execution permit or a bootstrap service.
"""
import json
import re
import ssl
import urllib.error
import urllib.request


class IdentityUnavailable(RuntimeError):
    pass


_SHA40 = re.compile(r'[0-9a-f]{40}\Z')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IdentityUnavailable('duplicate API JSON property')
        result[key] = value
    return result


class GitHubApi:
    """Owner-injected fetcher returns parsed JSON for fixed relative paths."""
    def __init__(self, repository, *, get_json):
        if type(repository) is not str or re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) is None:
            raise IdentityUnavailable('invalid pinned repository')
        if not callable(get_json):
            raise IdentityUnavailable('trusted HTTP transport missing')
        self.repository = repository
        self.get_json = get_json
        self.root = '/repos/' + repository

    def _read(self, endpoint):
        # Endpoint is constructed by this module only. Never accept a workflow URL.
        try:
            value = self.get_json(self.root + endpoint)
        except BaseException as exc:
            raise IdentityUnavailable('GitHub API unavailable') from exc
        if type(value) is not dict:
            raise IdentityUnavailable('invalid API response')
        return value

    @staticmethod
    def _ids(run_id, attempt):
        if type(run_id) is not int or type(attempt) is not int or not 0 < run_id <= 2**53-1 or not 0 < attempt <= 2**53-1:
            raise IdentityUnavailable('invalid run or attempt identifier')

    def get_run(self, run_id, attempt):
        self._ids(run_id, attempt)
        run = self._read(f'/actions/runs/{run_id}/attempts/{attempt}')
        if (type(run.get('id')) is not int or run['id'] != run_id or
            type(run.get('run_attempt')) is not int or run['run_attempt'] != attempt or
            run.get('event') != 'workflow_dispatch' or
            run.get('status') != 'in_progress' or
            type(run.get('repository')) is not dict or
            run['repository'].get('full_name') != self.repository):
            raise IdentityUnavailable('wrong Actions run identity/status')
        head_sha = run.get('head_sha')
        path = run.get('path')
        branch = run.get('head_branch')
        if (type(head_sha) is not str or _SHA40.fullmatch(head_sha) is None or
            type(path) is not str or not path.startswith('.github/workflows/') or
            path.count('@') != 1 or type(branch) is not str):
            raise IdentityUnavailable('missing run source identity')
        workflow_path, workflow_ref = path.split('@', 1)
        if workflow_ref != 'refs/heads/' + branch or not re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml', workflow_path):
            raise IdentityUnavailable('noncanonical dispatch workflow/ref')
        obj = self._read('/contents/' + workflow_path + '?ref=' + head_sha)
        blob_sha = obj.get('sha')
        if type(blob_sha) is not str or _SHA40.fullmatch(blob_sha) is None or obj.get('type') != 'file':
            raise IdentityUnavailable('unverifiable workflow source blob')
        return dict(workflow_ref=path, workflow_sha=blob_sha,
                    ref=workflow_ref, head_sha=head_sha,
                    run_id=run_id, run_attempt=attempt, repository=self.repository)

    def list_jobs(self, run_id, attempt):
        self._ids(run_id, attempt)
        data = self._read(f'/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page=1')
        jobs = data.get('jobs')
        if (type(data.get('total_count')) is not int or data['total_count'] < 0 or
            data['total_count'] > 100 or type(jobs) is not list or
            len(jobs) != data['total_count']):
            raise IdentityUnavailable('unbounded or incomplete attempt jobs')
        out = []
        for job in jobs:
            if type(job) is not dict:
                raise IdentityUnavailable('invalid job record')
            for field in ('id','run_id','run_attempt','runner_id'):
                if type(job.get(field)) is not int or job[field] <= 0 or job[field] > 2**53-1:
                    raise IdentityUnavailable('missing numeric job binding')
            if job['run_id'] != run_id or job['run_attempt'] != attempt:
                raise IdentityUnavailable('wrong job attempt')
            if job.get('status') not in ('queued','in_progress','completed','waiting'):
                raise IdentityUnavailable('unknown job state')
            out.append(dict(job_id=job['id'],run_id=run_id,run_attempt=attempt,
                            runner_id=job['runner_id'],status=job['status']))
        return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward a GitHub owner token to a redirect destination.
        return None


class OwnerAuthenticatedTransport:
    """No tokens/URLs accepted from a Workflow; owner provisions the token."""
    def __init__(self, *, token_provider, timeout=10):
        if not callable(token_provider) or type(timeout) not in (int, float) or not 0 < timeout <= 30:
            raise IdentityUnavailable('invalid trusted transport')
        self.token_provider, self.timeout = token_provider, timeout
        self.context = ssl.create_default_context()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self.context),
            _NoRedirect())

    def __call__(self, relative_path):
        if (type(relative_path) is not str or not relative_path.startswith('/repos/') or
            re.fullmatch(r'/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:actions/runs/[0-9]+/attempts/[0-9]+(?:/jobs\?per_page=100&page=1)?|contents/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml\?ref=[0-9a-f]{40})', relative_path) is None):
            raise IdentityUnavailable('unregistered GitHub API route')
        token = self.token_provider()
        if type(token) is not str or not token or any(c in '\r\n' for c in token):
            raise IdentityUnavailable('owner API token unavailable')
        req = urllib.request.Request('https://api.github.com' + relative_path,
                                     headers={'Accept':'application/vnd.github+json',
                                              'Authorization':'Bearer ' + token,
                                              'X-GitHub-Api-Version':'2022-11-28'})
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                if response.status != 200 or response.headers.get('Content-Type','').split(';')[0] != 'application/json':
                    raise IdentityUnavailable('unexpected GitHub response')
                body = response.read(1024*1024 + 1)
                if len(body) > 1024*1024:
                    raise IdentityUnavailable('oversized GitHub response')
                return json.loads(body, object_pairs_hook=_unique)
        except (urllib.error.URLError, TimeoutError, ValueError, UnicodeError) as exc:
            raise IdentityUnavailable('GitHub verification unavailable') from exc
