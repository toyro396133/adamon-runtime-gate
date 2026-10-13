"""Compile real bridge transport against upstream-shape doubles, NOT the complete fork."""
import argparse,json,pathlib,shutil,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
def compile_harness(sdk,newtonsoft,output):
    sdk=pathlib.Path(sdk).resolve();newtonsoft=pathlib.Path(newtonsoft).resolve();output=pathlib.Path(output).resolve();output.mkdir(parents=True,exist_ok=True)
    version=subprocess.check_output([str(sdk/'dotnet'),'--version'],text=True).strip()
    if version!='8.0.425':raise ValueError('SDK_VERSION_MISMATCH')
    refs=list((sdk/'packs/Microsoft.NETCore.App.Ref').glob('*/ref/net8.0/*.dll'))
    if not refs or not newtonsoft.is_file():raise ValueError('MISSING_REFERENCES')
    args=['-nologo','-target:exe','-langversion:latest','-out:'+str(output/'TransportHarness.dll')]+['-r:'+str(p) for p in refs]+['-r:'+str(newtonsoft)]+[str(ROOT/'overlays/P4ProtectedBridge.cs'),str(ROOT/'tests/UpstreamTypeDoubles.cs'),str(ROOT/'tests/TransportHarness.cs')]
    subprocess.run([str(sdk/'dotnet'),str(sdk/'sdk/8.0.425/Roslyn/bincore/csc.dll'),*args],check=True)
    shutil.copyfile(newtonsoft,output/'Newtonsoft.Json.dll')
    (output/'TransportHarness.runtimeconfig.json').write_text(json.dumps({'runtimeOptions':{'tfm':'net8.0','framework':{'name':'Microsoft.NETCore.App','version':'8.0.0'}}}))
    return output/'TransportHarness.dll'
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('sdk');p.add_argument('newtonsoft');p.add_argument('output');a=p.parse_args();print(compile_harness(a.sdk,a.newtonsoft,a.output))
