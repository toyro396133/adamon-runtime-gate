"""Apply only to an exact, clean public actions/runner checkout. No network or execution."""
import argparse,hashlib,json,pathlib,subprocess,shutil
BASE=pathlib.Path(__file__).resolve().parent
def apply(checkout):
    checkout=pathlib.Path(checkout).resolve();lock=json.loads((BASE/'upstream-lock.json').read_text())
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=checkout,text=True).strip()
    if head!=lock['commit']: raise ValueError('UPSTREAM_HEAD_MISMATCH')
    if subprocess.check_output(['git','status','--porcelain'],cwd=checkout,text=True).strip(): raise ValueError('UPSTREAM_DIRTY')
    for name,digest in lock['original_sources'].items():
        if hashlib.sha256((checkout/name).read_bytes()).hexdigest()!=digest: raise ValueError('UPSTREAM_BYTES_MISMATCH')
    patch=BASE/'runner-v4.patch'
    subprocess.run(['git','apply','--check',str(patch)],cwd=checkout,check=True)
    subprocess.run(['git','apply',str(patch)],cwd=checkout,check=True)
    shutil.copyfile(BASE/'overlays/P4ProtectedBridge.cs',checkout/'src/Runner.Common/P4ProtectedBridge.cs')
    return {'status':'PATCH_APPLIED_NOT_RUNTIME_VERIFIED','upstream_commit':head,'patch_sha256':hashlib.sha256(patch.read_bytes()).hexdigest()}
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('checkout');args=parser.parse_args();print(json.dumps(apply(args.checkout),sort_keys=True))
