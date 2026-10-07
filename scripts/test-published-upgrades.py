"""Every published stable >=1.0.6 is a mandatory actual-artifact upgrade source."""
import argparse, hashlib, json, pathlib, re, shutil, subprocess, sys, tarfile

parser=argparse.ArgumentParser()
parser.add_argument('--binary',required=True)
parser.add_argument('--target',required=True)
parser.add_argument('--model-dir',required=True)
parser.add_argument('--output-dir',required=True)
args=parser.parse_args()
root=pathlib.Path(args.output_dir).resolve(); root.mkdir(parents=True,exist_ok=True)
def command(*values):
    executable=shutil.which(values[0])
    assert executable,'required tool missing: '+values[0]
    return subprocess.check_output([executable,*values[1:]],text=True,timeout=60).strip()
releases=[]
for page in range(1,101):
    batch=json.loads(command('gh','api',f'repos/risense-ai/respire-cli/releases?per_page=100&page={page}'))
    releases.extend(batch)
    if len(batch)<100: break
else: raise RuntimeError('release inventory pagination limit exceeded')
def stable(tag):
    return bool(re.fullmatch(r'v\d+\.\d+\.\d+',tag)) and tuple(map(int,tag[1:].split('.'))) >= (1,0,6)
sources={item['tag_name']:item for item in releases if not item['draft'] and not item['prerelease'] and stable(item['tag_name'])}
registry=json.loads(command('npm','view','@rsrsai/cli','versions','--json'))
missing=[version for version in registry if stable('v'+version) and 'v'+version not in sources]
assert not missing,'published npm stable has no verifiable GitHub artifact: '+str(missing)
# No formal 1.0.6 was published in either registry. Keep its last actual DEV as an extra baseline.
if 'v1.0.6' not in sources:
    baseline=next((item for item in releases if item['tag_name']=='v1.0.6-dev.37075716045' and not item['draft']),None)
    assert baseline is not None,'1.0.6 compatibility baseline artifact missing'
    sources[baseline['tag_name']]=baseline
assert sources,'no upgrade source versions discovered'
report={'passed':False,'target':args.target,'candidate_sha256':hashlib.sha256(pathlib.Path(args.binary).read_bytes()).hexdigest(),'sources':[]}
try:
    for tag,release in sorted(sources.items()):
        folder=root/tag; folder.mkdir(exist_ok=True)
        extension='.exe' if 'windows' in args.target else ''
        names=[f'rsrs-{args.target}{extension}',f'rsrs-{args.target}-runtime.tar.gz',f'cli-build-{args.target}.json']
        assets={asset['name']:asset for asset in release['assets']}
        assert all(name in assets for name in names),'missing platform artifact: '+tag+' '+args.target
        needed=[]
        for name in names:
            digest=assets[name].get('digest')
            assert digest and digest.startswith('sha256:'),'published asset digest missing: '+tag+' '+name
            path=folder/name
            if not path.is_file(): needed.append(name)
            else:
                with path.open('rb') as stream:
                    if hashlib.file_digest(stream,'sha256').hexdigest()!=digest[7:]: needed.append(name)
        if needed:
            subprocess.run(['gh','release','download',tag,'--repo','risense-ai/respire-cli','--dir',str(folder),'--clobber',*[value for name in needed for value in ['--pattern',name]]],check=True,timeout=180)
        for name in names:
            digest=assets[name].get('digest')
            assert digest and digest.startswith('sha256:'),'published asset digest missing: '+tag+' '+name
            with (folder/name).open('rb') as stream: assert hashlib.file_digest(stream,'sha256').hexdigest()==digest[7:]
        manifest=json.loads((folder/names[2]).read_text())
        assert manifest['version']==tag[1:] and manifest['target']==args.target
        for name,key in zip(names[:2],['binary_sha256','runtime_sha256']):
            with (folder/name).open('rb') as stream: assert hashlib.file_digest(stream,'sha256').hexdigest()==manifest[key]
        with tarfile.open(folder/names[1]) as bundle: bundle.extractall(folder,filter='data')
        old=folder/('rsrs'+extension)
        shutil.copyfile(folder/names[0],old); old.chmod(old.stat().st_mode | 0o111)
        result=folder/'results'
        subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('test-real-m3-account-switch.py')),
            '--binary',args.binary,'--seed-binary',str(old),'--expect-in-process','--model-dir',args.model_dir,'--output-dir',str(result)],check=True)
        checks=json.loads((result/'real-account-return-verification.json').read_text())
        assert all(check['passed'] and check['binary_sha256']==report['candidate_sha256'] for check in checks),'candidate changed during upgrade validation'
        report['sources'].append({'version':tag[1:],'formal':stable(tag),'passed':True,'report':str(result/'real-account-return-verification.json')})
    report['passed']=True
finally:
    (root/'published-upgrades.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
