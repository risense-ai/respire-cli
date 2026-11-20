"""Exercise actual-artifact upgrades for the selected critical or full gate."""
import argparse, hashlib, json, os, pathlib, platform, re, shutil, subprocess, sys, tarfile
from concurrent.futures import ThreadPoolExecutor
from published_upgrade_policy import DATABASE_DEV_CHECKPOINTS, platform_applicability, select_upgrade_sources
from published_upgrade_evidence import validate_upgrade_result
from native_fixture_process import add_runtime_arguments, runtime_inputs

parser=argparse.ArgumentParser()
download_only='--download-only' in sys.argv
parser.add_argument('--download-only',action='store_true',help='Download and verify only the fixed draft baseline; never execute product binaries')
parser.add_argument('--draft-baseline-cache',type=pathlib.Path,help='Same-run verified fixed draft assets and metadata; missing or corrupt cache fails closed')
parser.add_argument('--binary',required=not download_only)
parser.add_argument('--target',required=True)
parser.add_argument('--model-dir',required=not download_only)
parser.add_argument('--legacy-model-dir',required=not download_only)
parser.add_argument('--client2-gui-report',type=pathlib.Path,help='Same-run verified desktop used to upgrade the latest Windows 1.x library')
parser.add_argument('--output-dir',required=True)
parser.add_argument('--profile',choices=['critical','full'],default='full')
parser.add_argument('--source',action='append',default=[],help='Diagnostic subset only: exact selected tag or latest formal; never full coverage')
parser.add_argument('--include-legacy-baselines',action='store_true',help='Manual historical diagnostics only: include unpublished draft and DEV baselines')
macos_shards=parser.add_mutually_exclusive_group()
macos_shards.add_argument('--plan-macos-shards',action='store_true',help='Freeze the full Apple Silicon source and byte identities without running upgrades')
macos_shards.add_argument('--macos-shard-plan',type=pathlib.Path,help='Run one exact --source from the same-attempt Apple Silicon plan')
add_runtime_arguments(parser)
args=parser.parse_args()
if (args.download_only or args.draft_baseline_cache) and not args.include_legacy_baselines:
    parser.error('Draft baseline diagnostics require --include-legacy-baselines')
if not args.download_only: runtime_inputs(args,[args.binary])
if args.client2_gui_report and (args.download_only or args.source or args.profile!='full' or
        args.target!='x86_64-pc-windows-msvc' or not args.runtime_binary):
    parser.error('Client2 database acceptance requires the full standalone Windows release gate')
if args.plan_macos_shards or args.macos_shard_plan:
    import macos_upgrade_shards as shards
    if (not __debug__ or args.target!=shards.TARGET or args.profile!='full' or not args.runtime_binary
            or args.include_legacy_baselines or args.download_only):
        parser.error('Apple Silicon shard mode requires the full standalone published-source profile with assertions')
    if args.plan_macos_shards and args.source:
        parser.error('The Apple Silicon plan requires the complete source inventory')
    if args.macos_shard_plan and (len(args.source)!=1 or args.source==['latest']):
        parser.error('A shard requires exactly one source tag from the plan')
    if args.macos_shard_plan and (sys.platform!='darwin' or platform.machine()!='arm64'
            or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted'):
        parser.error('Apple Silicon shards require a native GitHub-hosted runner')
upgrade_contract='standalone-v1' if args.runtime_binary else 'legacy-shim-v1'
root=pathlib.Path(args.output_dir).resolve(); root.mkdir(parents=True,exist_ok=True)
if args.macos_shard_plan and any(root.iterdir()):
    parser.error('A shard requires an empty output directory')
def command(*values):
    executable=shutil.which(values[0])
    assert executable,'required tool missing: '+values[0]
    return subprocess.check_output([executable,*values[1:]],text=True,encoding='utf-8',timeout=60).strip()
releases=[]
if args.macos_shard_plan:
    saved_plan=args.macos_shard_plan.read_bytes()
    frozen_plan=json.loads(saved_plan)
    releases=[{'tag_name':tag,'id':item['release_id'],'draft':False,'prerelease':'-' in tag,
               'assets':[{'name':name,**asset} for name,asset in item['assets'].items()]}
              for tag,item in frozen_plan['inputs'].items()]
elif not args.download_only:
    for page in range(1,101):
        batch=json.loads(command('gh','api',f'repos/risense-ai/respire-cli/releases?per_page=100&page={page}'))
        releases.extend(batch)
        if len(batch)<100: break
    else: raise RuntimeError('release inventory pagination limit exceeded')
def stable(tag):
    return bool(re.fullmatch(r'v\d+\.\d+\.\d+',tag)) and tuple(map(int,tag[1:].split('.'))) >= (1,0,6)
sources={item['tag_name']:item for item in releases if not item['draft'] and not item['prerelease'] and stable(item['tag_name'])}
formal_sources=sorted(sources, key=lambda tag: tuple(map(int,tag[1:].split('.'))))
if args.macos_shard_plan:
    registry=frozen_plan['inventory']['registry_formal_versions']
else:
    registry=[] if args.download_only else sorted(set(json.loads(command('npm','view','@rsrsai/cli','versions','--json'))) |
                    set(json.loads(command('npm','view','rsrs-cli','versions','--json'))))
missing=[version for version in registry if stable('v'+version) and 'v'+version not in sources]
assert not missing,'published npm stable has no verifiable GitHub artifact: '+str(missing)
# Database checkpoints are mandatory in both profiles, independently of optional diagnostics.
if not args.download_only:
    for tag in DATABASE_DEV_CHECKPOINTS:
        baseline=next((item for item in releases if item['tag_name']==tag and not item['draft']),None)
        assert baseline is not None,'database DEV checkpoint artifact missing: '+tag
        sources[tag]=baseline
# The complete 1.0.10 draft is an explicit compatibility baseline, not a formal release.
additional_draft_baselines=[]
if args.include_legacy_baselines and args.profile=='full' and 'v1.0.10' not in formal_sources:
    # Draft assets retain their release/asset IDs even when the tag endpoint omits them.
    if args.draft_baseline_cache:
        assert args.draft_baseline_cache.resolve()==root,'draft cache must use the upgrade output directory'
        baseline=json.loads((root/'draft-baseline.json').read_text(encoding='utf-8'))
    else:
        baseline=json.loads(command('gh','api','repos/risense-ai/respire-cli/releases/403872621'))
    assert baseline['id']==403872621,'fixed draft release ID mismatch'
    assert baseline['tag_name']=='v1.0.10' and baseline['draft'],'1.0.10 compatibility baseline identity mismatch'
    sources[baseline['tag_name']]=baseline
    additional_draft_baselines.append(baseline['tag_name'])
assert sources,'no upgrade source versions discovered'
report={'passed':False,'target':args.target,'candidate_sha256':None if args.download_only else hashlib.sha256(pathlib.Path(args.binary).read_bytes()).hexdigest(),
        'upgrade_contract':upgrade_contract,
        'profile':args.profile,'selected_sources':[],'full_coverage':False,'all_published_sources_covered':False,
        'published_formal_sources':formal_sources,
        'additional_draft_baselines':additional_draft_baselines,
        'database_dev_checkpoints':{} if args.download_only else DATABASE_DEV_CHECKPOINTS,
        'unpublished_draft_stables':sorted({item['tag_name'] for item in releases if item['draft'] and stable(item['tag_name'])} | set(additional_draft_baselines)),
        'registry_formal_versions':sorted(version for version in registry if stable('v'+version)),
        'sources':[]}

if args.plan_macos_shards or args.macos_shard_plan:
    model_cache=str(pathlib.Path(__file__).with_name('native-model-cache.py'))
    for model in dict.fromkeys((args.model_dir,args.legacy_model_dir)):
        subprocess.run([sys.executable,model_cache,'verify','--model-dir',model,'--legacy-dir',args.legacy_model_dir],check=True)
    identity={'cli_sha256':report['candidate_sha256'],'runtime_sha256':args.runtime_sha256,
              'runtime_version':args.runtime_version,'model_key':command(sys.executable,model_cache,'key'),
              'manifest_sha256':os.environ['RSRS_PUBLISHED_ASSETS_SHA256'],
              'bundle_sha256':os.environ['RSRS_PUBLISHED_BUNDLE_SHA256'],
              'fixture_sha':command('git','rev-parse','HEAD')}
    plan=shards.make_plan(report,sources,releases,identity)
    if args.plan_macos_shards:
        shards.write_json(root/'macos-shard-plan.json',plan)
        sys.exit(0)
    shards.require(frozen_plan==plan and args.source[0] in plan['inputs'],
                   'Shard plan or expected source differs from the current verified inputs')

def verify_upgrade(source,client2_args=()):
    tag,release=source
    folder=root/tag; folder.mkdir(exist_ok=True)
    extension='.exe' if 'windows' in args.target else ''
    names=[f'rsrs-{args.target}{extension}',f'rsrs-{args.target}-runtime.tar.gz',f'cli-build-{args.target}.json']
    assets={asset['name']:asset for asset in release['assets']}
    not_applicable=platform_applicability(tag,args.target,assets)
    if not_applicable:
        return {'version':tag[1:],'formal':tag in formal_sources,'status':'not-applicable','reason':not_applicable}
    needed=[]
    for name in names:
        digest=assets[name].get('digest')
        assert digest and digest.startswith('sha256:'),'published asset digest missing: '+tag+' '+name
        path=folder/name
        if not path.is_file(): needed.append(name)
        else:
            with path.open('rb') as stream:
                if hashlib.file_digest(stream,'sha256').hexdigest()!=digest[7:]: needed.append(name)
    if release['draft'] and args.draft_baseline_cache:
        assert not needed,'fixed draft cache missing or corrupt; authenticated download is isolated'
    if needed:
        download_env=os.environ.copy()
        download_env['GODEBUG']=(download_env.get('GODEBUG')+',' if download_env.get('GODEBUG') else '')+'http2client=0'
        if release['draft'] or args.macos_shard_plan:
            for name in needed:
                with (folder/name).open('wb') as output:
                    subprocess.run(['gh','api',f"repos/risense-ai/respire-cli/releases/assets/{assets[name]['id']}",
                        '-H','Accept: application/octet-stream'],stdout=output,check=True,timeout=180,env=download_env)
        else:
            subprocess.run(['gh','release','download',tag,'--repo','risense-ai/respire-cli','--dir',str(folder),'--clobber',*[value for name in needed for value in ['--pattern',name]]],check=True,timeout=180,env=download_env)
    for name in names:
        digest=assets[name].get('digest')
        assert digest and digest.startswith('sha256:'),'published asset digest missing: '+tag+' '+name
        with (folder/name).open('rb') as stream: assert hashlib.file_digest(stream,'sha256').hexdigest()==digest[7:]
    manifest=json.loads((folder/names[2]).read_text())
    assert manifest['version']==tag[1:] and manifest['target']==args.target
    for name,key in zip(names[:2],['binary_sha256','runtime_sha256']):
        with (folder/name).open('rb') as stream: assert hashlib.file_digest(stream,'sha256').hexdigest()==manifest[key]
    if args.download_only:
        assert tag=='v1.0.10' and release['draft'],'download-only must retain the fixed draft baseline'
        (root/'draft-baseline.json').write_text(json.dumps(release),encoding='utf-8')
        return
    with tarfile.open(folder/names[1]) as bundle: bundle.extractall(folder,filter='data')
    old=folder/('rsrs'+extension)
    shutil.copyfile(folder/names[0],old); old.chmod(old.stat().st_mode | 0o111)
    result=folder/('results-client2' if client2_args else 'results')
    runtime_args=(['--runtime-binary',str(args.runtime_binary),'--runtime-sha256',args.runtime_sha256,
                   '--runtime-version',args.runtime_version] if args.runtime_binary else [])
    checkpoint_args=['--database-dev-checkpoint',tag] if tag in DATABASE_DEV_CHECKPOINTS else []
    shard_args=['--seed-source',tag] if args.macos_shard_plan else []
    architecture_args=[] if args.runtime_binary else ['--expect-supervised-worker']
    subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('test-real-m3-account-switch.py')),
        '--binary',args.binary,'--seed-binary',str(old),'--model-dir',args.model_dir,
        '--legacy-model-dir',args.legacy_model_dir,'--output-dir',str(result),*runtime_args,*checkpoint_args,*architecture_args,*shard_args,*client2_args],check=True)
    checks=json.loads((result/'real-account-return-verification.json').read_text())
    row=validate_upgrade_result(checks,tag=tag,formal=tag in formal_sources,upgrade_contract=upgrade_contract,
        candidate_sha256=report['candidate_sha256'],runtime_sha256=args.runtime_sha256,runtime_version=args.runtime_version,
        report_path=result/'real-account-return-verification.json',client2_sha256=client2_args[-1] if client2_args else None)
    if args.macos_shard_plan:
        shards.validate_shard_process(checks[0],plan,tag)
    return row


if args.download_only:
    assert args.profile=='full' and not args.draft_baseline_cache,'download-only requires the fixed full draft source'
    verify_upgrade(('v1.0.10',sources['v1.0.10']))
    sys.exit(0)

try:
    selected=select_upgrade_sources(sources,args.target,args.profile)
    if args.source:
        requested=[]
        for tag in args.source:
            if tag=='latest':
                tag=next((tag for tag in reversed(formal_sources) if platform_applicability(tag,args.target,
                    [asset['name'] for asset in sources[tag]['assets']]) is None),None)
            assert tag in selected and tag not in requested, 'diagnostic source is absent or duplicated: '+str(tag)
            requested.append(tag)
        selected={tag:selected[tag] for tag in requested}
        report['diagnostic_sources']=requested
    report['selected_sources']=sorted(selected)
    # Legacy macOS model workers have a fixed 30-second deadline; avoid competing model loads.
    with ThreadPoolExecutor(max_workers=1 if sys.platform == 'darwin' else 2) as pool:
        for outcome in pool.map(verify_upgrade, sorted(selected.items())):
            report['sources'].append(outcome)
    first_platform_release=(args.target=='x86_64-apple-darwin' and all(
        platform_applicability(tag,args.target,[asset['name'] for asset in source['assets']]) is not None
        for tag,source in sources.items()))
    assert first_platform_release or any(item.get('passed') is True for item in report['sources']),'no actual applicable upgrade was exercised'
    if args.client2_gui_report:
        desktop=json.loads(args.client2_gui_report.read_text(encoding='utf-8'))
        executable=args.client2_gui_report.parent/'respire-windows-amd64.exe'
        digest=desktop['exe_sha256']
        assert desktop['status']=='connectivity-passed' and desktop['cleanup_exit_confirmed'] is True, 'desktop GUI validation did not pass'
        independence=desktop['cli_independence']
        assert independence['mode']=='external-fixture-only' and independence['process_start_trace_clear'] is True, 'desktop CLI independence was not verified'
        assert desktop['cli_sha256']==report['candidate_sha256'], 'desktop validation used a different external CLI fixture'
        assert hashlib.sha256(executable.read_bytes()).hexdigest()==digest, 'validated desktop executable changed'
        latest=next(tag for tag in reversed(formal_sources) if selected.get(tag) and
                    any('v'+item['version']==tag and item.get('passed') is True for item in report['sources']))
        report['client2_historical_upgrade']=verify_upgrade((latest,selected[latest]),
            ('--client2-binary',str(executable),'--client2-sha256',digest))
        assert report['client2_historical_upgrade']['passed'] is True, 'desktop historical database upgrade did not pass'
    report['first_platform_release']=first_platform_release
    if first_platform_release:
        report['upgrade_status']='not-applicable: first Intel macOS release; fresh inference is validated separately'
    applicable=[item for item in report['sources'] if item.get('passed') is True]
    report['post_upgrade_sync_checked']=bool(applicable) and all(item.get('post_upgrade_sync_checked') is True for item in applicable)
    if args.macos_shard_plan:
        report['macos_shard']={'source':args.source[0],'plan_sha256':hashlib.sha256(saved_plan).hexdigest(),
                              'check_run_id':shards.check_run_id(),
                              'identity':identity,'process_report_sha256':shards.file_digest(pathlib.Path(applicable[0]['report']))}
    report['passed']=True
    report['full_coverage']=report['all_published_sources_covered']=args.profile=='full' and not args.source
finally:
    (root/'published-upgrades.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
