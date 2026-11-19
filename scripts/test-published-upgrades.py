"""Exercise actual-artifact upgrades for the selected critical or full gate."""
import argparse, hashlib, json, os, pathlib, re, shutil, subprocess, sys, tarfile
from concurrent.futures import ThreadPoolExecutor
from published_upgrade_policy import DATABASE_DEV_CHECKPOINTS, platform_applicability, select_upgrade_sources
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
add_runtime_arguments(parser)
args=parser.parse_args()
if (args.download_only or args.draft_baseline_cache) and not args.include_legacy_baselines:
    parser.error('Draft baseline diagnostics require --include-legacy-baselines')
if not args.download_only: runtime_inputs(args,[args.binary])
if args.client2_gui_report and (args.download_only or args.source or args.profile!='full' or
        args.target!='x86_64-pc-windows-msvc' or not args.runtime_binary):
    parser.error('Client2 database acceptance requires the full standalone Windows release gate')
upgrade_contract='standalone-v1' if args.runtime_binary else 'legacy-shim-v1'
root=pathlib.Path(args.output_dir).resolve(); root.mkdir(parents=True,exist_ok=True)
def command(*values):
    executable=shutil.which(values[0])
    assert executable,'required tool missing: '+values[0]
    return subprocess.check_output([executable,*values[1:]],text=True,encoding='utf-8',timeout=60).strip()
releases=[]
if not args.download_only:
    for page in range(1,101):
        batch=json.loads(command('gh','api',f'repos/risense-ai/respire-cli/releases?per_page=100&page={page}'))
        releases.extend(batch)
        if len(batch)<100: break
    else: raise RuntimeError('release inventory pagination limit exceeded')
def stable(tag):
    return bool(re.fullmatch(r'v\d+\.\d+\.\d+',tag)) and tuple(map(int,tag[1:].split('.'))) >= (1,0,6)
sources={item['tag_name']:item for item in releases if not item['draft'] and not item['prerelease'] and stable(item['tag_name'])}
formal_sources=sorted(sources, key=lambda tag: tuple(map(int,tag[1:].split('.'))))
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
        if release['draft']:
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
    architecture_args=[] if args.runtime_binary else ['--expect-supervised-worker']
    subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('test-real-m3-account-switch.py')),
        '--binary',args.binary,'--seed-binary',str(old),'--model-dir',args.model_dir,
        '--legacy-model-dir',args.legacy_model_dir,'--output-dir',str(result),*runtime_args,*checkpoint_args,*architecture_args,*client2_args],check=True)
    checks=json.loads((result/'real-account-return-verification.json').read_text())
    assert isinstance(checks,list) and len(checks)==1,'expected one candidate upgrade report'
    check=checks[0]
    assert isinstance(check,dict) and all(check.get(name) is True for name in [
        'passed','real_model','distinct_vault_keys',
        'original_records_preserved','original_sync_work_preserved','urk_preserved',
        'old_records_decrypted','post_upgrade_recall_checked','encrypted_tombstones_preserved',
    ]),'required real upgrade checks missing or failed'
    assert check.get('seed_vault_versions')==[1,3] and all(type(value) is int for value in check['seed_vault_versions']), 'historical v1/v3 session coverage missing'
    if checkpoint_args:
        checkpoint=check.get('database_dev_checkpoint')
        assert isinstance(checkpoint,dict) and checkpoint.get('tag')==tag \
            and checkpoint.get('special_state_seeded') is True \
            and checkpoint.get('special_state_preserved') is True \
            and checkpoint.get('verified_accounts')==['main','alternate'], 'database checkpoint-specific state was not verified'
        if args.runtime_binary:
            assert checkpoint.get('post_sync_special_state_preserved') is True \
                and checkpoint.get('sync_verified_accounts')==['main'], 'database checkpoint state was not verified after real sync'
    assert check.get('historical_credential_migration_actor')=='fixture', 'explicit fixture credential migration missing'
    custody=check.get('host_credential_custody')
    assert isinstance(custody,dict) and custody.get('required') is True and custody.get('cleanup_passed') is True, 'historical credential custody or cleanup unconfirmed'
    accounts=custody.get('verified_accounts')
    assert isinstance(accounts,list) and len(accounts)==2 and all(isinstance(item,dict) for item in accounts), 'historical account custody evidence missing'
    assert [(item.get('account'),item.get('vault_version')) for item in accounts]==[('main',1),('alternate',3)], 'historical credential account coverage differs'
    assert all(item.get('urk_preserved') is True for item in accounts), 'historical credential custody changed a data key'
    cleanup=check.get('native_credential_cleanup')
    assert isinstance(cleanup,dict) and cleanup.get('passed') is True and cleanup.get('remaining_entries')==[], 'native credential cleanup unconfirmed'
    assert check.get('upgrade_contract')==upgrade_contract,'unknown, missing or incompatible upgrade contract'
    if upgrade_contract=='standalone-v1':
        assert all(check.get(name) is True for name in [
            'standalone_runtime_evidence','runtime_artifact_reused','normal_reopen_checked','stale_endpoint_archived',
        ]),'required standalone upgrade checks missing or failed'
        assert all(check.get(name) is False for name in [
            'old_rpc_checked','forced_restart_checked','live_owner_restart_rejected','safe_restart_checked',
            'supervised_worker_checked','in_process_checked','global_engine_preserved',
        ]),'database upgrade must not claim delegated host or legacy checks'
        assert check.get('legacy_handoff_actor') is None, 'database upgrade must not require a running legacy host'
        assert check.get('coverage_scope')=='historical-database', 'historical database coverage scope missing'
        assert check.get('host_checks_delegated_to')=='resident-concurrency', 'current host checks must remain in the resident fixture'
        assert check.get('post_upgrade_sync_checked') is True, 'historical schema synchronization or cleanup was not verified'
        sync=check.get('post_upgrade_sync')
        assert isinstance(sync,dict) and all(sync.get(field) is True for field in ('original_urk_preserved',
            'existing_keys_registered','source_push','independent_pull_decrypted','reverse_marker_source_pull',
            'original_active_preserved','tombstones_propagated','pending_work_acknowledged')), 'historical bidirectional sync evidence incomplete'
        assert isinstance(check.get('cloud_cleanup'),dict) and check['cloud_cleanup'].get('passed') is True \
            and check['cloud_cleanup'].get('remaining_users')==[], 'historical sync cloud cleanup unconfirmed'
        assert check.get('runtime_mode')=='standalone_runtime','standalone Runtime mode missing'
        assert check.get('runtime_binary_sha256')==args.runtime_sha256,'upgrade Runtime digest differs'
        assert check.get('runtime_version')==args.runtime_version,'upgrade Runtime version differs'
        receipts=check.get('runtime_identity_receipts')
        assert isinstance(receipts,list) and receipts and all(isinstance(item,dict) for item in receipts),\
            'upgrade Runtime identity receipts missing'
    else:
        assert all(check.get(name) is True for name in [
            'forced_restart_checked','old_rpc_checked','supervised_worker_checked','global_engine_preserved',
        ]),'required legacy shim upgrade checks missing or failed'
    assert check.get('binary_sha256')==report['candidate_sha256'],'candidate changed during upgrade validation'
    assert check.get('client2_sha256')==(client2_args[-1] if client2_args else None),'desktop upgrade actor differs'
    if client2_args:
        assert check.get('client2_native_credential_migration') is True, 'desktop native credential migration was not exercised'
    assert check.get('engine')=='cpu','upgrade did not verify real CPU inference'
    sequence=check.get('sequence')
    assert isinstance(sequence,list) and [step['account'] for step in sequence]==['main','alternate','main'],'upgrade account sequence differs'
    for step in sequence:
        rows=step.get('model_rows')
        assert isinstance(rows,dict) and set(rows)=={'embedder','model index'} and all(
            row.get('status')=='ok' for row in rows.values()),'upgrade model readiness checks missing or failed'
    return {'version':tag[1:],'formal':tag in formal_sources,'passed':True,'upgrade_contract':upgrade_contract,
            'database_dev_checkpoint':check.get('database_dev_checkpoint'),
            'coverage_scope':check.get('coverage_scope'),
            'normal_reopen_checked':check.get('normal_reopen_checked') is True,
            'stale_endpoint_archived':check.get('stale_endpoint_archived') is True,
            'client2_sha256':check.get('client2_sha256'),
            'host_checks_delegated_to':check.get('host_checks_delegated_to'),
            'post_upgrade_sync_checked':check.get('post_upgrade_sync_checked') is True,
            'report':str(result/'real-account-return-verification.json')}

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
        assert desktop['cli_sha256']==report['candidate_sha256'], 'desktop validation used a different CLI'
        assert hashlib.sha256(executable.read_bytes()).hexdigest()==digest, 'validated desktop executable changed'
        latest=next(tag for tag in reversed(formal_sources) if selected.get(tag) and
                    any('v'+item['version']==tag and item.get('passed') is True for item in report['sources']))
        report['client2_historical_upgrade']=verify_upgrade((latest,selected[latest]),
            ('--client2-binary',str(executable),'--client2-sha256',digest))
        assert report['client2_historical_upgrade']['passed'] is True, 'desktop historical database upgrade did not pass'
    report['first_platform_release']=first_platform_release
    if first_platform_release:
        report['upgrade_status']='not-applicable: first Intel macOS release; fresh inference is validated separately'
    report['passed']=True
    applicable=[item for item in report['sources'] if item.get('passed') is True]
    report['post_upgrade_sync_checked']=bool(applicable) and all(item.get('post_upgrade_sync_checked') is True for item in applicable)
    report['full_coverage']=report['all_published_sources_covered']=args.profile=='full' and not args.source
finally:
    (root/'published-upgrades.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
