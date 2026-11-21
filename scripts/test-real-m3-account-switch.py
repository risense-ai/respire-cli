"""Read-only real M3 cache; disposable profiles and owned runtime port only."""
import argparse, faulthandler, hashlib, json, os, pathlib, secrets, socket, sqlite3, subprocess, sys, tempfile, time, urllib.request
from native_fixture_process import (install_official_runtime, install_published_runtime, FixtureCancelled, ForegroundOverlapProbe, WorkerInspector, captured_run,
    add_runtime_arguments, runtime_inputs, runtime_report, verify_runtime_health, process_start_id, canonical_scope_path, same_existing_path)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from contextlib import closing
from types import SimpleNamespace

def recover_fixture_urk(session, factors):
    version = session.get('vault_version', 1)
    assert version in (1, 2, 3, 4), 'unsupported fixture vault version'
    wrapped = session['wrapped_urk']
    if version == 4:
        kek = vault_crypto.v4_kek(factors['super'], session['kdf_salt'], wrapped)
    else:
        kek = vault_crypto.legacy_kek(version, factors['pass'] if version == 1 else factors['super'],
            factors['secret'] if version == 1 else factors['secret_key'] if version == 3 else '',
            session['kdf_salt'], current=wrapped.startswith(vault_crypto.PREFIX))
    return AESGCM(kek).decrypt(bytes.fromhex(session['urk_nonce']), vault_crypto.encrypted_bytes(wrapped), None)


def legacy_custody_alias(profile, session_bytes):
    return 'legacy-'+hashlib.sha256(canonical_scope_path(profile).encode('utf-8')+session_bytes).hexdigest()


def migrate_fixture_custody(profile, keys, plan, expected_urk):
    alias,version,slots=plan
    original=(profile/'session.json').read_bytes()
    session=json.loads(original)
    assert legacy_custody_alias(profile,original)==alias, 'historical session changed before fixture custody'
    backend=keys.credential_backend
    assert backend in ('native','secret_service'), 'fixture custody requires a persistent provider'
    factors={('secret' if version==1 else 'secret_key') if slot=='legacy-secret' else slot:value
        for slot,value in slots.items()}
    assert recover_fixture_urk(session,factors)==expected_urk, 'fixture custody original URK differs'
    for slot,value in slots.items():
        assert ('rsrs',slot+':'+alias) in keys.entries, 'fixture custody slot was not reserved'
        keys.put('rsrs',slot+':'+alias,value)
    migrated={key:value for key,value in session.items() if key not in ('pass','super','secret','secret_key')}
    migrated.update(keyring_account=alias,keyring_backend=backend,legacy_secret_backend=backend)
    assert (profile/'session.json').read_bytes()==original, 'historical session changed during fixture custody'
    (profile/'session.json').write_text(json.dumps(migrated),encoding='utf-8')


def custody_consumer_error(output):
    # Emit only known source messages; arbitrary output may contain decrypted data or credentials.
    body=(output.stdout+output.stderr).decode('utf-8',errors='replace')
    markers=('runtime request belongs to another installation',
        'runtime RPC response scope mismatch', 'scope_mismatch',
        'unlock Runtime does not own the selected profile',
        'runtime owner roots or installation identity do not match maintenance',
        'unlock Runtime process identity changed', 'unlock Runtime image changed',
        'host session credential read failed', 'legacy secret credential is missing or empty',
        'Runtime session credentials are unavailable', 'failed to decrypt',
        'NoStorageAccess', 'PlatformFailure', 'NoEntry')
    matched=sorted((body.index(marker),marker) for marker in markers if marker in body)
    return 'CLI host custody consumer failed: '+json.dumps({'returncode':output.returncode,
        'source_chain':[marker for _,marker in matched] or ['unclassified'],
        'stdout_bytes':len(output.stdout),'stderr_bytes':len(output.stderr)})


def verify_fixture_custody(profile, keys, plan, expected_urk, binary, env):
    alias,version,slots=plan
    session=json.loads((profile/'session.json').read_bytes())
    backend='secret_service' if sys.platform.startswith('linux') else 'native'
    assert session.get('keyring_account')==alias, 'custody alias differs from the reserved profile/session identity'
    assert session.get('vault_version',1)==version, 'custody changed the historical vault version'
    assert session.get('keyring_backend')==session.get('legacy_secret_backend')==backend, 'custody selected an unverified provider'
    assert not {'pass','super','secret','secret_key'} & session.keys(), 'custody retained inline sensitive factors'
    if sys.platform.startswith('linux'): keys.verify_owner()
    recovered={}
    for slot,expected in slots.items():
        assert ('rsrs',slot+':'+alias) in keys.entries, 'custody slot is not reserved by this fixture'
        if sys.platform=='darwin':
            # These synthetic fixture entries are readable without changing product ACLs.
            metadata=keys._security(keys.root,['find-generic-password','-s','rsrs','-a',slot+':'+alias,str(keys.keychain)])
            assert metadata.returncode==0, 'custody exact slot metadata missing'
        else:
            value=keys.read('rsrs',slot+':'+alias)
            assert value==expected, 'custody slot readback differs from the original factor'
            name=('secret' if version==1 else 'secret_key') if slot=='legacy-secret' else slot
            recovered[name]=value
    if sys.platform=='darwin':
        # Check the wrap with original factors, then require the CLI to unlock the same data via host slots.
        original_factors={(('secret' if version==1 else 'secret_key') if slot=='legacy-secret' else slot): value
            for slot,value in slots.items()}
        assert recover_fixture_urk(session,original_factors)==expected_urk, 'host custody changed the URK'
        assert set(slots)=={'pass' if version==1 else 'super','legacy-secret'}, 'CLI custody proof has an unconsumed slot'
        # RSRS_DATA_DIR identifies the installation; client.json selects its account.
        clean_env=dict(env)
        installation=pathlib.Path(env['RSRS_DATA_DIR'])
        config_bytes=(installation/'client.json').read_bytes()
        assert same_existing_path(json.loads(config_bytes)['data_dir'],profile), 'custody consumer account is not selected'
        for prefix in ('RSRS_','ONEMEMORY_','RESPIRE_'):
            for suffix in ('SUPER','PASS','SECRET','KDF_SALT','WRAPPED_URK','URK_NONCE'):
                assert prefix+suffix not in env, 'resident custody consumer has a factor override'
        database = profile/'rsrs.db'
        if not database.exists(): database = profile/'onememory.db'
        with closing(sqlite3.connect(database.as_uri()+'?mode=ro',uri=True)) as db:
            row=db.execute('SELECT id,ciphertext,nonce FROM memories WHERE deleted=0 ORDER BY id LIMIT 1').fetchone()
        assert row is not None, 'custody consumer has no original ciphertext'
        expected=json.loads(vault_crypto.decrypt_content(expected_urk,*row[1:]))['content']
        shown=captured_run([str(binary),'--json','show',row[0]],env=clean_env,timeout=120)
        assert shown.returncode==0, custody_consumer_error(shown)
        result=json.loads(shown.stdout)
        assert not result.get('errors') and result.get('status') not in ('error','failed','fail'), custody_consumer_error(shown)
        assert result.get('details',{}).get('entry',{}).get('content')==expected, 'CLI host custody could not decrypt original data'
        assert (installation/'client.json').read_bytes()==config_bytes, 'CLI custody consumer changed account routing'
        assert json.loads((profile/'session.json').read_bytes())==session, 'CLI custody consumer changed the session'
    else:
        assert recover_fixture_urk(session,recovered)==expected_urk, 'host custody changed the URK'
    return {'vault_version':version,'primary_slot_readback':sys.platform!='darwin',
        'legacy_secret_readback':sys.platform!='darwin','urk_preserved':True,
        'consumer':'cli_authenticated_decryption' if sys.platform=='darwin' else 'exact_slot_readback'}


def library_state(snapshot, factors):
    rows, _, session_bytes = snapshot
    session = json.loads(session_bytes)
    urk = recover_fixture_urk(session, factors)
    records = []
    for memory_id, ciphertext, nonce, dirty, deleted in rows[0]:
        plaintext = vault_crypto.decrypt_content(urk, ciphertext, nonce)
        records.append((memory_id, plaintext, dirty, deleted))
    return records, rows[1], urk


def assert_historical_database_seed(snapshot_value):
    memories, outbox, _ = snapshot_value[0]
    assert any(row[1] and row[2] and row[4] == 0 for row in memories), 'historical seed has no encrypted active record'
    assert any(row[1] and row[2] and row[3] == 1 and row[4] == 1 for row in memories), 'historical seed has no encrypted pending tombstone'
    assert outbox, 'historical seed has no pending synchronization work'


def database_checkpoint_state(profile, checkpoint, snapshot_value, records):
    if checkpoint == 'v1.0.11-dev.1':
        links = []
        for memory_id, plaintext, _, _ in records:
            payload = json.loads(plaintext)
            links.append((memory_id, payload.get('supersedes', ''),
                          payload.get('superseded_by', ''), tuple(sorted(payload.get('see_also', [])))))
        return {'kind': 'legacy_relation_payload', 'links': sorted(links),
                'legacy_domain': all(not row[1].startswith(vault_crypto.PREFIX) for row in snapshot_value[0][0])}
    if checkpoint != 'v1.0.17-dev.6':
        raise ValueError('unsupported database checkpoint: ' + checkpoint)
    database = profile / 'rsrs.db'
    if not database.exists():
        database = profile / 'onememory.db'
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as db:
        witness = db.execute('SELECT schema_version,library_id,seq,ts,action,entry_id,previous_entry_id,'
            'before_digest,after_digest,prev,hash FROM witness_log ORDER BY seq').fetchall()
        requests = db.execute('SELECT request_id FROM query_log WHERE request_id IS NOT NULL ORDER BY request_id').fetchall()
        feedback = db.execute('SELECT q.request_id,f.memory_id,f.good,f.source,f.marked_at,f.revision '
            'FROM query_feedback f JOIN query_log q ON q.id=f.query_log_id '
            'ORDER BY q.request_id,f.memory_id').fetchall()
        recovery_table = db.execute("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='sync_recovery_intents')").fetchone()[0]
    return {'kind': 'witness_feedback', 'witness': witness, 'requests': requests,
            'feedback': feedback, 'recovery_table': bool(recovery_table)}


def assert_database_checkpoint_preserved(before, after):
    assert before['kind'] == after['kind'], 'database checkpoint kind changed'
    if before['kind'] == 'legacy_relation_payload':
        current = {row[0]: row for row in after['links']}
        assert all(current.get(row[0]) == row for row in before['links']), 'encrypted historical relation fields changed'
    else:
        assert after['witness'][:len(before['witness'])] == before['witness'], 'historical witness prefix changed'
        assert set(before['requests']) <= set(after['requests']), 'historical query request identity lost'
        assert set(before['feedback']) <= set(after['feedback']), 'historical explicit feedback changed'


parser=argparse.ArgumentParser()
parser.add_argument('--binary',action='append',required=True)
parser.add_argument('--model-dir',required=True)
parser.add_argument('--model-file',choices=['model_quantized.onnx','model_fp16.onnx'],default='model_quantized.onnx')
parser.add_argument('--legacy-model-file',choices=['model_fp16.onnx','model_quantized.onnx'],default='model_fp16.onnx')
parser.add_argument('--legacy-model-dir',help='Read-only baseline cache containing real FP16 and quantized files')
parser.add_argument('--output-dir',required=True)
architecture=parser.add_mutually_exclusive_group()
architecture.add_argument('--expect-in-process',action='store_true',help='Historical binaries without an inference worker')
architecture.add_argument('--expect-supervised-worker',action='store_true',help='Verify one owned worker and its lifetime/SQLite boundary')
parser.add_argument('--resident-stress',action='store_true',help='Exercise concurrent recall, short writes, lightweight reads and background indexing')
parser.add_argument('--expect-background-threads',type=int,choices=range(1,17),help='Verify the actual loaded worker foreground/background policy')
parser.add_argument('--seed-binary',help='Create both libraries with this published older binary, then verify the database upgrade')
parser.add_argument('--seed-source',help='Verify and record the exact historical release tag used for a shard')
parser.add_argument('--client2-binary', type=pathlib.Path, help='Install and start Runtime using the verified desktop executable')
parser.add_argument('--client2-sha256')
parser.add_argument('--database-dev-checkpoint', choices=['v1.0.11-dev.1', 'v1.0.17-dev.6'])
add_runtime_arguments(parser)
args=parser.parse_args()
if args.seed_source and not args.seed_binary:
    parser.error('--seed-source requires --seed-binary')
if args.database_dev_checkpoint and not args.seed_binary:
    parser.error('--database-dev-checkpoint requires an authenticated historical --seed-binary')
database_upgrade = bool(args.seed_binary and args.runtime_binary)
if args.client2_binary or args.client2_sha256:
    if not (database_upgrade and args.client2_binary and args.client2_sha256 and os.name == 'nt'):
        parser.error('Client2 requires verified Windows desktop bytes and a historical database source')
    args.client2_binary = args.client2_binary.resolve(strict=True)
    assert hashlib.sha256(args.client2_binary.read_bytes()).hexdigest() == args.client2_sha256, 'desktop digest differs'
if database_upgrade and (args.expect_in_process or args.expect_supervised_worker
        or args.resident_stress or args.expect_background_threads is not None):
    parser.error('historical database upgrades leave worker and lifecycle fault checks to the resident fixture')
runtime_config=args
if sys.platform.startswith('linux') and args.seed_binary and os.environ.get('RSRS_SS_FIXTURE_BUS')!='private':
    os.execvpe('dbus-run-session', ['dbus-run-session','--',sys.executable,*sys.argv],
        dict(os.environ,RSRS_SS_FIXTURE_BUS='private'))
faulthandler.enable()
# A cloud container's PID 1 may not reap orphans. Adopt workers after a forced
# host termination so this fixture can verify and reap their actual exit.
if sys.platform.startswith('linux'):
    import ctypes
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(36,1,0,0,0)!=0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(),'cannot enable fixture child subreaper')
# Asynchronous stack dumps can race live frames (CPython #116008); fixture calls retain hard deadlines.
BASE=pathlib.Path(args.output_dir).resolve()
BASE.mkdir(parents=True,exist_ok=True)
import cryptography, importlib.metadata, importlib.util, psutil
vault_spec=importlib.util.spec_from_file_location('upgrade_vault_crypto', pathlib.Path(__file__).with_name('dev-legacy-vault-smoke.py'))
vault_crypto=importlib.util.module_from_spec(vault_spec)
vault_spec.loader.exec_module(vault_crypto)
(BASE/'fixture-dependencies.json').write_text(json.dumps({
    'python':sys.version,'cryptography':cryptography.__version__,'psutil':psutil.__version__,
    'psutil_source':json.loads(importlib.metadata.distribution('psutil').read_text('direct_url.json') or 'null'),
},indent=2),encoding='utf-8')
CACHE=pathlib.Path(args.model_dir).resolve()
BINARIES=[pathlib.Path(path).resolve() for path in args.binary]
runtime_inputs(args,BINARIES)
MODEL_HASHES={'model_quantized.onnx':'0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d',
    'model_fp16.onnx':'4f1a646a3d4f39985589e9991a717044ede8278617fe55e3d246838bc05055e9'}
def verify_model(cache,model):
    for name,expected in [('tokenizer.json','6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790'),('onnx/'+model,MODEL_HASHES[model])]:
        with (cache/name).open('rb') as stream: assert hashlib.file_digest(stream,'sha256').hexdigest()==expected
verify_model(CACHE,args.model_file)
LEGACY_CACHE=pathlib.Path(args.legacy_model_dir).resolve() if args.legacy_model_dir else CACHE
if args.seed_binary:
    verify_model(LEGACY_CACHE,args.legacy_model_file)
    if args.model_file=='model_quantized.onnx': verify_model(LEGACY_CACHE,'model_quantized.onnx')
reports = []
for binary in BINARIES:
    if args.runtime_binary: args.runtime_identity_receipts=[]
    root = BASE / ('account-return-real-' + str(time.time_ns()))
    if os.name == 'posix' and sys.platform != 'darwin':
        # Keep fixture paths short and isolated from the CI report
        # directory for cross-platform tools; keep the owned
        # fixture in a short workspace directory and retain reports in BASE.
        root = pathlib.Path(os.environ['RUNNER_TEMP'] if args.seed_binary else pathlib.Path.cwd()) / ('rsrs-up-' + secrets.token_hex(6))
    main = root / '.rsrs'
    alternate = main / 'accounts/alternate'
    root.mkdir(mode=0o700)
    main.mkdir(mode=0o700)
    (main / 'accounts').mkdir(mode=0o700)
    alternate.mkdir(mode=0o700)
    entropy = secrets.token_bytes(18)
    code = 'A3-' + '-'.join(entropy.hex().upper()[i:i+6] for i in range(0,36,6))
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0)); port = listener.getsockname()[1]
    env = {key: value for key, value in os.environ.items()
           if key not in ('GH_TOKEN', 'GITHUB_TOKEN')}
    for suffix in ['CLIENT_ONLY','NO_AUTOSTART','RUNTIME_WORKER','CORE_TEST_MODE','RPC_TOKEN','ENGINE','ADDR','TOKEN','JSON','ORT_DEBUG',
                   'SUPER','PASS','SECRET','KDF_SALT','WRAPPED_URK','URK_NONCE']:
        for prefix in ['RSRS_', 'ONEMEMORY_', 'RESPIRE_']:
            env.pop(prefix + suffix,None)
    env.update(HOME=str(root), USERPROFILE=str(root), RSRS_DATA_DIR=str(main), RSRS_RPC_PORT=str(port),
        RSRS_SUPER=code,RSRS_NO_AUTOSYNC='1',RSRS_UPDATE_CHECK='0',RSRS_M3_DIR=str(CACHE))
    if args.seed_binary: env.pop('RSRS_SUPER')
    env['RSRS_RUNTIME_BIN']=str(args.runtime_binary or binary)
    if args.runtime_binary: env['LC_ALL']='C'
    runtime_installed_after_legacy_data = False
    runtime_artifact_reused = False
    stale_endpoint_archived = False
    keys=None
    custody_slots={}
    custody_receipts={}
    components_started=False
    network_smoke=None
    network_evidence=None
    provider_account_switch=None
    def run(*args, allow_failure=False, timeout=120, cancel=None):
        result = captured_run([str(binary),'--json',*args],env=env,timeout=timeout,cancel=cancel)
        if result.returncode and not allow_failure: raise RuntimeError(result.stdout.decode(errors='replace')+result.stderr.decode(errors='replace'))
        envelope=json.loads(result.stdout)
        envelope['_fixture_timing']=result.fixture_timing
        command=next((word for word in args if not word.startswith('-')),None)
        if runtime_config.runtime_binary and result.returncode==0 and command in ('model','remember','recall','show','doctor','status'):
            observe_runtime()
        return envelope
    def run_client2(action, *arguments):
        desktop_env = {key: value for key, value in env.items() if key != 'RSRS_RUNTIME_BIN'}
        system_root = pathlib.Path(os.environ['SystemRoot'])
        system_path = (system_root / 'System32', system_root)
        desktop_env.update(PATH=os.pathsep.join(map(str, system_path)), RSRS_BIN_DIR=str(main / 'bin'))
        cli_paths = [p / 'rsrs.exe' for p in (main / 'bin', args.client2_binary.parent, *system_path)]
        assert not any(os.path.lexists(p) for p in cli_paths), 'Client2 must start without an installed CLI'
        result = captured_run([str(args.client2_binary),'--headless',action,*arguments],env=desktop_env,timeout=960)
        assert result.returncode==0, f'Client2 {action} failed with exit {result.returncode}'
        response = json.loads(result.stdout)
        assert response.get('ok') is True, f'Client2 {action} did not confirm success'
        assert not any(os.path.lexists(p) for p in cli_paths), 'Client2 unexpectedly installed a CLI'
        return response.get('result')
    def wait_index_ready(timeout=180):
        deadline = time.monotonic() + timeout
        while True:
            doctor = run('doctor', allow_failure=True)
            rows = {item['name']: item for item in doctor['items'] if item['name'] in ['embedder', 'model index']}
            if len(rows) == 2 and all(item['status'] == 'ok' for item in rows.values()):
                return rows
            assert time.monotonic() < deadline, rows
            time.sleep(.25)

    def snapshot(profile):
        database = profile/'rsrs.db'
        if not database.exists(): database = profile/'onememory.db'
        with closing(sqlite3.connect(database)) as db:
            assert db.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'database integrity check failed'
            rows = [db.execute(query).fetchall() for query in ['SELECT id,ciphertext,nonce,dirty,deleted FROM memories ORDER BY id',
                'SELECT * FROM sync_outbox ORDER BY seq','SELECT * FROM core_artifacts ORDER BY memory_id,model']]
        artifacts = sorted((path.name,hashlib.sha256(path.read_bytes()).hexdigest()) for path in (profile/'core-index').iterdir())
        return (rows,artifacts,(profile/'session.json').read_bytes())
    def observe_runtime(health=None):
        if health is None:
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}/api/health',headers={'X-Respire-Health':'runtime-v1'}),timeout=2) as response:
                health=json.load(response)
        profile=pathlib.Path(json.loads((main/'client.json').read_text())['data_dir']) if (main/'client.json').exists() else main
        verify_runtime_health(runtime_config,health,main,profile)
        return health
    old_runtime=None
    old_rpc_checked=False
    old_rpc_authenticated=False
    legacy_client_rejected=False
    source_rpc_checked=False
    legacy_handoff_actor=None
    live_owner_restart_rejected=False
    public_config={'addr':'https://fixture.invalid','autosync':False,'custom':'preserve-upgrade-fixture'}
    def select(profile):
        (main/'client.json').write_text(json.dumps({**public_config,'data_dir':str(profile)}),encoding='utf-8')
    worker_identities=[]
    inspector=None
    stop_failure=None
    def checked_worker(health):
        global inspector
        if args.runtime_binary: observe_runtime(health)
        if sys.platform=='win32':
            if inspector is None:
                inspector=WorkerInspector(root/'boundary-inspector')
            identity=inspector.inspect({'host_pid':health['pid'],
                'worker_pid':health['inference']['worker_pid'],'binary':str(binary),
                'runtime_binary':str(args.runtime_binary) if args.runtime_binary else None,
                'process_start_id':health.get('process_start_id')})
            if identity not in worker_identities: worker_identities.append(identity)
            return identity
        import psutil
        host=psutil.Process(health['pid'])
        children=[child for child in host.children(recursive=True)
                  if not (sys.platform=='win32' and child.name().lower()=='conhost.exe')]
        assert len(children)==1, 'expected exactly one supervised Core worker'
        worker=children[0]
        assert worker.pid==health['inference']['worker_pid'] and worker.ppid()==host.pid
        assert '--core-worker-internal' in worker.cmdline()
        assert same_existing_path(worker.exe(),host.exe())
        assert not any(pathlib.Path(file.path).name in ('rsrs.db','lock.db') for file in worker.open_files())
        assert not {'GH_TOKEN','GITHUB_TOKEN','OPENAI_API_KEY','RSRS_SUPER'} & worker.environ().keys()
        identity=(worker.pid,worker.create_time())
        if identity not in worker_identities: worker_identities.append(identity)
        return identity
    def confirm_workers_exited(identities):
        import psutil
        deadline=time.monotonic()+10
        for pid,created in identities:
            while True:
                try: alive=psutil.Process(pid).create_time()==created
                except psutil.NoSuchProcess: alive=False
                if not alive: break
                if sys.platform.startswith('linux'):
                    try: reaped,_=os.waitpid(pid,os.WNOHANG)
                    except ChildProcessError: reaped=0
                    if reaped==pid: break
                assert time.monotonic()<deadline, 'owned Core worker survived its host: '+str(pid)
                time.sleep(.02)
    try:
        if sys.platform == 'darwin' or args.seed_binary:
            keyring_script='dev-migration-secret-service.py' if sys.platform.startswith('linux') else 'dev-migration-keyring.py'
            keyring_spec=importlib.util.spec_from_file_location('upgrade_native_keyring',
                pathlib.Path(__file__).with_name(keyring_script))
            keyring_backend=importlib.util.module_from_spec(keyring_spec)
            keyring_spec.loader.exec_module(keyring_backend)
            keys=keyring_backend.create(root/'keyring-home')
            if sys.platform.startswith('linux'): keys.configure_business_env(env)
            else: keys.configure_env(env)
        components_started=True
        if not (args.seed_binary and args.runtime_binary):
            installed = install_published_runtime(binary, env)
            if installed is None and args.runtime_binary:
                installed = install_official_runtime(binary, env, args.runtime_version, args.runtime_sha256)
            if installed is not None: args.runtime_binary = installed
        expected_urks={}
        recovery_factors={}
        seed_vault_versions=[]
        for profile in [main, alternate]:
            salt,nonce,urk=secrets.token_bytes(16),secrets.token_bytes(12),secrets.token_bytes(32)
            version=(1 if profile==main else 3) if args.seed_binary else 4
            factors={'super':code}
            session={'user':'fixture-'+str(time.time_ns()),'vault_version':version,'kdf_salt':salt.hex()}
            if version in (1,3):
                field='secret' if version==1 else 'secret_key'
                factors[field]=secrets.token_hex(32)
                if version==1: factors['pass']=secrets.token_urlsafe(32)
                session.update({field:factors[field], 'pass':factors['pass']} if version==1 else
                    {field:factors[field], 'super':code})
                kek=vault_crypto.legacy_kek(version,factors['pass'] if version==1 else code,factors[field],salt.hex())
            else:
                kek=vault_crypto.v4_kek(code,salt.hex())
            session.update(wrapped_urk=AESGCM(kek).encrypt(nonce,urk,None).hex(),urk_nonce=nonce.hex())
            (profile/'session.json').write_text(json.dumps(session),encoding='utf-8')
            expected_urks[str(profile)]=urk
            recovery_factors[str(profile)]=factors
            seed_vault_versions.append(version)
        assert len(set(expected_urks.values()))==2, 'fixture accounts must have distinct URKs'
        seed_env={**env,'RSRS_M3_DIR':str(LEGACY_CACHE)}
        if args.seed_binary: seed_env['RSRS_RUNTIME_BIN']=str(pathlib.Path(args.seed_binary).resolve())
        # Historical artifacts predate RSRS_*; keep their inputs explicit and
        # isolated instead of accidentally testing the operator's default library.
        for key, value in list(seed_env.items()):
            if key.startswith(('RSRS_', 'ONEMEMORY_', 'RESPIRE_')):
                seed_env['ONEMEMORY_' + key[5:]] = value
        if not (args.seed_binary and args.runtime_binary):
            run('--direct','model','engine','cpu')
            stopped=captured_run([str(binary),'--runtime-internal','--stop'],env=env,timeout=50)
            assert stopped.returncode==0,'direct engine preparation runtime stop failed'
            global_engine=(main/'inference.json').read_bytes()
        for profile in [main,alternate]:
            select(profile)
            if args.seed_binary:
                def seed_command(*command):
                    seeded=captured_run([str(pathlib.Path(args.seed_binary).resolve()),'--json','--direct',*command],env=seed_env,timeout=180)
                    assert seeded.returncode==0,seeded.stdout.decode(errors='replace')+seeded.stderr.decode(errors='replace')
                    return seeded
                seed_version = json.loads(seed_command('v').stdout)['summary']['version']
                if args.seed_source:
                    assert 'v' + seed_version == args.seed_source, 'historical seed version differs from the shard source'
                # These published versions select M3 without activating an empty index.
                if seed_version in {'1.0.11-dev.1', '1.0.11', '1.0.12', '1.0.15', '1.0.16',
                                    '1.0.17-dev.6', '1.0.18', '1.0.19', '1.0.20'}:
                    assert not any((profile/name).exists() for name in ('rsrs.db','onememory.db')), 'historical seed profile is not empty'
                else:
                    seed_command('model','activate','m3')
                seed_command('remember','Real account return fixture '+profile.name,'--title',profile.name,'--importance','important','--force')
                if args.database_dev_checkpoint == 'v1.0.11-dev.1':
                    first_ids = {row[0] for row in snapshot(profile)[0][0]}
                    assert len(first_ids) == 1, 'relation checkpoint requires exactly one original entry'
                    seed_command('remember','Independent checkpoint companion for network routing policy',
                        '--title','checkpoint-companion','--importance','important','--force')
                    peer_ids = {row[0] for row in snapshot(profile)[0][0]} - first_ids
                    assert len(peer_ids) == 1, 'historical CLI did not create the relation companion'
                    seed_command('remember','Replacement checkpoint conclusion preserving encrypted relationship fields',
                        '--title','checkpoint-replacement','--importance','important','--force',
                        '--supersedes',next(iter(first_ids)),'--see-also',next(iter(peer_ids)))
                elif args.database_dev_checkpoint == 'v1.0.17-dev.6':
                    recalled = json.loads(seed_command('recall','Real account return fixture '+profile.name,'--limit','3').stdout)
                    request = recalled['summary']['query_log_id']
                    assert isinstance(request, str) and request, 'historical recall did not expose its request identity'
                    memory_ids = [row[0] for row in snapshot(profile)[0][0]]
                    assert len(memory_ids) == 1, 'feedback checkpoint requires its original candidate'
                    seed_command('query-log','mark',memory_ids[0],'--good','--query-log-id',request,'--source','human')
                tombstone = json.loads(seed_command('remember','Historical encrypted deletion '+profile.name,
                    '--title','upgrade-tombstone','--importance','important','--force').stdout)['summary']['id']
                assert isinstance(tombstone, str) and tombstone, 'historical tombstone seed has no identity'
                seed_command('forget',tombstone)
            else:
                run('--direct','remember','Real account return fixture '+profile.name,'--title',profile.name,'--importance','important','--force')
                if args.runtime_binary:
                    # Durable remember may return before background embeddings finish.
                    # Wait on this selected profile's live owner before stopping it.
                    wait_index_ready()
                    index_files=list((profile/'core-index').iterdir())
                    assert index_files and all(path.is_file() and path.stat().st_size>0 for path in index_files), 'seed index artifacts missing or empty'
                    # --direct forwards to a resident owner; drain it before raw fixture profile selection.
                    stopped=captured_run([str(binary),'--runtime-internal','--stop'],env=env,timeout=50)
                    assert stopped.returncode==0,'direct seed runtime stop failed'
        if not args.seed_binary:
            stopped=captured_run([str(binary),'--runtime-internal','--stop'],env=env,timeout=50)
            assert stopped.returncode==0,'direct seed runtime stop failed'
        original = {str(profile):snapshot(profile) for profile in [main,alternate]}
        assert [json.loads(original[str(profile)][2]).get('vault_version',1) for profile in [main,alternate]]==seed_vault_versions, 'historical preparation replaced the selected session formats'
        original_state={name:library_state(value,recovery_factors[name]) for name,value in original.items()}
        if args.seed_binary:
            for profile in [main, alternate]:
                assert_historical_database_seed(original[str(profile)])
        checkpoint_before = {}
        if args.database_dev_checkpoint:
            for profile in [main, alternate]:
                state = database_checkpoint_state(profile, args.database_dev_checkpoint,
                    original[str(profile)], original_state[str(profile)][0])
                if state['kind'] == 'legacy_relation_payload':
                    assert state['legacy_domain'] and any(row[1] for row in state['links']) \
                        and any(row[2] for row in state['links']) and any(row[3] for row in state['links']), \
                        'checkpoint lacks old-domain encrypted association state'
                else:
                    assert state['witness'] and state['requests'] and state['feedback'] \
                        and not state['recovery_table'], 'checkpoint lacks its intermediate witness/feedback state'
                    assert original_state[str(profile)][1], 'checkpoint has no pending synchronization work'
                checkpoint_before[str(profile)] = state
        assert all(state[2]==expected_urks[name] for name,state in original_state.items()), 'seed changed the fixture URK'
        if args.seed_binary:
            for profile in [main,alternate]:
                session_bytes=original[str(profile)][2]
                session=json.loads(session_bytes)
                assert session.get('keyring_account') is None, 'historical seed already selected a credential alias'
                version=session.get('vault_version',1)
                alias=legacy_custody_alias(profile,session_bytes)
                primary='pass' if version==1 else 'super'
                slots={primary:session[primary], 'legacy-secret':session['secret' if version==1 else 'secret_key']}
                if version==3 and 'pass' in session: slots['pass']=session['pass']
                for slot in slots: keys.reserve('rsrs',slot+':'+alias)
                custody_slots[str(profile)]=(alias,version,slots)
        select(main)
        if args.seed_binary and not database_upgrade:
            log=(root/'old-runtime.log').open('wb')
            web_help=subprocess.check_output([args.seed_binary,'web','--help'],env=seed_env,text=True,encoding='utf-8',timeout=30)
            runtime_args=['web','--internal','--no-open','--port',str(port)] if '--port' in web_help else ['--runtime-internal']
            old_runtime=subprocess.Popen([str(pathlib.Path(args.seed_binary).resolve()),*runtime_args],env=seed_env,stdout=log,stderr=log)
            log.close()
            for attempt in range(200):
                assert old_runtime.poll() is None,('published old runtime exited before upgrade (exit '+str(old_runtime.returncode)+'): '+
                    (root/'old-runtime.log').read_text(encoding='utf-8',errors='replace')[-4000:])
                try:
                    headers={}
                    token=main/'runtime/token'
                    if token.exists(): headers['Authorization']='Bearer '+token.read_text().strip()
                    request=urllib.request.Request(f'http://127.0.0.1:{port}/api/health',headers=headers)
                    with urllib.request.urlopen(request,timeout=1) as response: health=json.load(response)
                    assert health['pid']==old_runtime.pid
                    break
                except OSError: time.sleep(.1)
            else: raise RuntimeError('published old runtime did not become ready')
            # Historical components prepare data; only the upgraded stack is tested next.
            original_token=token.read_bytes() if token.is_file() else None
            legacy_records={path:(path.read_bytes() if path.is_file() else None) for path in
                [main/'runtime/endpoint.json',token,main/'client.json',main/'inference.json',
                 main/'runtime/autostart/registration.json']}
            legacy_data={str(profile):snapshot(profile) for profile in [main,alternate]}
            old_owner=psutil.Process(old_runtime.pid)
            old_birth=old_owner.create_time()
            old_start=process_start_id(old_runtime.pid)
            assert same_existing_path(old_owner.exe(),args.seed_binary)
            if not args.runtime_binary:
                old_status=run('--client-only','status')
                assert old_status.get('status')=='ok','new client could not read the old runtime through HTTP RPC'
                assert old_runtime.poll() is None,'client-only RPC replaced or stopped the old runtime'
                request=urllib.request.Request(f'http://127.0.0.1:{port}/api/health',headers=headers)
                with urllib.request.urlopen(request,timeout=2) as response: after_rpc=json.load(response)
                assert after_rpc['pid']==old_runtime.pid,'client-only RPC changed runtime ownership'
                assert (token.read_bytes() if token.is_file() else None)==original_token,'client-only RPC changed the old token file'
                old_rpc_checked=True
                old_rpc_authenticated=bool(original_token and original_token.strip())
            if args.runtime_binary:
                # Test setup owns this historical child. This is not product takeover evidence.
                old_children=[(child.pid,child.create_time()) for child in old_owner.children(recursive=True)]
                assert process_start_id(old_runtime.pid)==old_start
                old_runtime.terminate()
                old_runtime.wait(timeout=15)
                confirm_workers_exited([(old_runtime.pid,old_birth),*old_children])
                for path in [main/'runtime/endpoint.json',token]:
                    before=legacy_records[path]
                    if path.exists():
                        assert before is not None and path.read_bytes()==before
                        path.unlink()
                old_runtime=None
                legacy_handoff_actor='fixture'
        if args.seed_binary and args.runtime_binary:
            # Historical writers have exited. Reuse the independently verified
            # artifact; installation/download behavior is a per-target host check.
            legacy_data={str(profile):snapshot(profile) for profile in [main,alternate]}
            endpoint = main/'runtime/endpoint.json'
            endpoint.parent.mkdir(exist_ok=True)
            # The recorded PID is live but belongs to this test driver, while the old port is free.
            stale_endpoint = json.dumps({'v':1,'pid':os.getpid(),'url':f'http://127.0.0.1:{port}'}).encode()
            with endpoint.open('xb') as stream:
                stream.write(stale_endpoint)
            if args.client2_binary:
                obsolete_receipt = main/'runtime.json'
                with obsolete_receipt.open('xb') as stream:
                    stream.write(b'obsolete Runtime selection')
                run_client2('install-runtime', args.runtime_version)
                assert obsolete_receipt.read_bytes()==b'obsolete Runtime selection', 'desktop changed the obsolete receipt'
                selected = run_client2('bootstrap-status')['installed_runtime']
                assert selected == {'version': args.runtime_version, 'sha256': args.runtime_sha256}, 'desktop did not select the exact Runtime fixture'
                installed = main/'bin/runtime'/args.runtime_version/'rsrs-runtime.exe'
                assert hashlib.sha256(installed.read_bytes()).hexdigest()==args.runtime_sha256, 'desktop installed different Runtime bytes'
                env['RSRS_RUNTIME_BIN'] = str(installed)
                env['RSRS_BIN_DIR'] = str(main / 'bin')
            else:
                installed = install_published_runtime(binary, env)
            assert installed is not None, 'database upgrade requires the verified managed or published Runtime artifact'
            args.runtime_binary = installed
            assert endpoint.read_bytes()==stale_endpoint, 'Runtime preparation changed the old endpoint'
            assert {str(profile):snapshot(profile) for profile in [main,alternate]} == legacy_data, 'Runtime installation changed old account data'
            runtime_installed_after_legacy_data = True
            runtime_artifact_reused = True
        if args.seed_binary:
            # The desktop case leaves the main session for the actual startup host to migrate.
            for profile in [main,alternate]:
                if args.client2_binary and profile == main:
                    continue
                before=snapshot(profile)
                migrate_fixture_custody(profile,keys,custody_slots[str(profile)],expected_urks[str(profile)])
                after=snapshot(profile)
                assert after[:2]==before[:2], 'fixture custody changed historical database or indexes'
                assert library_state(after,recovery_factors[str(profile)])==original_state[str(profile)], 'fixture custody changed original records, sync work or URK'
        if args.seed_binary and args.runtime_binary:
            if args.client2_binary:
                run_client2('start')
                desktop_owner = observe_runtime()
                assert desktop_owner['store_ready'], 'Client2 did not unlock the historical database'
                run('--client-only','status')
                run_client2('rpc-status')
                assert observe_runtime()['instance_id']==desktop_owner['instance_id'], 'the two hosts changed the serving Runtime'
            else:
                run('runtime','start')
            archived = list(endpoint.parent.glob('endpoint.stopped-*.json'))
            assert len(archived)==1 and archived[0].read_bytes()==stale_endpoint, 'startup did not archive the old endpoint'
            assert endpoint.read_bytes()!=stale_endpoint, 'new Runtime still uses the old endpoint record'
            stale_endpoint_archived = True
            run('--direct','model','engine','cpu')
            stopped=captured_run([str(binary),'--runtime-internal','--stop'],env=env,timeout=50)
            if stopped.returncode:
                stop_failure={'phase':'direct_engine_preparation','returncode':stopped.returncode,
                    'timing':dict(stopped.fixture_timing),
                    'runtime_identity_receipt_index':len(args.runtime_identity_receipts)-1,
                    'stdout':'redaction_unavailable','stderr':'redaction_unavailable'}
                try:
                    # Reuse the existing bounded credential redactor; never attach raw output or fixture files.
                    support_spec=importlib.util.spec_from_file_location('stop_diagnostic_support',
                        pathlib.Path(__file__).with_name('dev-legacy-vault-smoke.py'))
                    support=importlib.util.module_from_spec(support_spec)
                    support_spec.loader.exec_module(support)
                    redactor=object.__new__(support.Smoke)
                    redactor.diagnostic_secrets={code,entropy.hex()}
                    for factors in recovery_factors.values():
                        redactor.diagnostic_secrets.update(factors.values())
                    for profile in (main,alternate):
                        redactor.diagnostic_secrets.update(value for value in
                            json.loads((profile/'session.json').read_bytes()).values()
                            if isinstance(value,str) and value)
                    for stream in ('stdout','stderr'):
                        body=getattr(stopped,stream)
                        output=subprocess.CompletedProcess(stopped.args,stopped.returncode,
                            body if stream=='stdout' else b'',body)
                        stop_failure[stream]=redactor.redacted_cli_error(env,output)
                except Exception:
                    # Redaction failure must neither publish raw bytes nor hide the original stop failure.
                    pass
            assert stopped.returncode==0,'direct engine preparation runtime stop failed'
            global_engine=(main/'inference.json').read_bytes()
        statuses=[]
        visited=set()
        generation_changes={}
        for account, profile in [('main',main),('alternate',alternate),('main',main)]:
            previous_workers=list(worker_identities)
            daemon=getattr(keys,'daemon',None)
            exit_before=daemon.poll() if daemon is not None else None
            provider_checkpoints={}
            stage='account_use'
            try:
                run('account','use',account)
                if daemon is not None: provider_checkpoints['account_use']=daemon.poll()
                stage='runtime_handoff'
                if args.expect_supervised_worker and previous_workers:
                    confirm_workers_exited(previous_workers)
                if old_runtime is not None:
                    assert old_runtime.wait(timeout=20)==0,'old runtime did not exit gracefully'
                stage='model_engine'
                assert run('model','engine')['summary']['engine']=='cpu'
                if daemon is not None: provider_checkpoints['model_engine']=daemon.poll()
                if not database_upgrade:
                    assert (main/'inference.json').read_bytes()==global_engine
                    assert not (alternate/'inference.json').exists()
                # A real model change may rebuild derived indexes once; never source data.
                stage='index_ready'
                rows = wait_index_ready()
                if daemon is not None: provider_checkpoints['index_ready']=daemon.poll()
                stage='credential_custody'
                if args.seed_binary:
                    custody_receipts[str(profile)]={'account':account, **verify_fixture_custody(
                        profile,keys,custody_slots[str(profile)],expected_urks[str(profile)],binary,env)}
            except Exception:
                if daemon is not None:
                    provider_account_switch={'fixture_account':account,
                        'exit_before':exit_before,'exit_after':daemon.poll(),
                        'failed_stage':stage,'exit_after_checkpoint':provider_checkpoints}
                raise
            if args.seed_binary and str(profile) not in visited:
                current=snapshot(profile)
                baseline=original[str(profile)]
                assert library_state(current,recovery_factors[str(profile)])==original_state[str(profile)], 'migration changed original records, sync work or URK'
                generation_changes[str(profile)]=current[0][2]!=baseline[0][2] or current[1]!=baseline[1]
                original[str(profile)]=current
            visited.add(str(profile))
            if args.expect_in_process or args.expect_supervised_worker:
                import psutil
                probe_stdout=tempfile.TemporaryFile()
                probe_stderr=tempfile.TemporaryFile()
                pending=subprocess.Popen([str(binary),'--json','model','probe','--model','m3'],env=env,stdout=probe_stdout,stderr=probe_stderr)
                checks=0
                deadline=time.monotonic()+120
                try:
                    while pending.poll() is None:
                        assert time.monotonic()<deadline,'native probe exceeded the acceptance deadline'
                        start=time.monotonic()
                        with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}/api/health',headers={'X-Respire-Health':'runtime-v1'}),timeout=2) as response:
                            health=json.load(response)
                        assert time.monotonic()-start < 2,'health blocked behind native inference'
                        if args.expect_supervised_worker:
                            identity=checked_worker(health)
                            if checks: assert identity==probe_worker,'warm native probe replaced its worker'
                            probe_worker=identity
                        else:
                            children=psutil.Process(health['pid']).children(recursive=True)
                            children=[child for child in children if not (sys.platform=='win32' and child.name().lower()=='conhost.exe')]
                            assert not children, 'runtime spawned an inference child: '+str([child.name() for child in children])
                        checks+=1
                        time.sleep(.05)
                    pending.wait(timeout=5)
                    probe_stdout.seek(0); probe_stderr.seek(0)
                    stdout,stderr=probe_stdout.read(),probe_stderr.read()
                    assert pending.returncode==0,stdout.decode(errors='replace')+stderr.decode(errors='replace')
                    assert checks>0,'native inference responsiveness was not exercised'
                finally:
                    if pending.poll() is None:
                        pending.kill(); pending.wait(timeout=5)
                    probe_stdout.close(); probe_stderr.close()
            else:
                run('model','probe','--model','m3')
            if args.expect_background_threads is not None:
                # Model/index metadata may be ready before the worker heartbeat.
                deadline=time.monotonic()+10
                policy=None
                while policy is None and time.monotonic()<deadline:
                    with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}/api/health',headers={'X-Respire-Health':'runtime-v1'}),timeout=2) as response:
                        thread_health=json.load(response)
                    policy=thread_health.get('inference',{}).get('intra_threads')
                    if policy is None: time.sleep(.05)
                assert policy=={'foreground':1,'background':args.expect_background_threads}, 'loaded worker thread policy differs: '+str(policy)
                (BASE/('inference-threads-'+account+'.json')).write_text(json.dumps(policy),encoding='utf-8')
            recalled=run('recall','Real account return fixture','--titles')
            assert recalled.get('items'),'real recall returned no seeded entry'
            if args.expect_supervised_worker:
                with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}/api/health',headers={'X-Respire-Health':'runtime-v1'}),timeout=2) as response:
                    assert checked_worker(json.load(response))==probe_worker,'warm recall replaced its worker'
            doctor=run('doctor',allow_failure=True)
            rows={item['name']:item for item in doctor['items'] if item['name'] in ['embedder','model index']}
            assert len(rows)==2 and all(item['status']=='ok' for item in rows.values()),rows
            assert same_existing_path(json.loads((main/'client.json').read_text())['data_dir'],profile)
            config=json.loads((main/'client.json').read_text())
            if not database_upgrade:
                assert all(config.get(key)==value for key,value in public_config.items()),'upgrade/switch changed public API settings'
            assert library_state(snapshot(profile),recovery_factors[str(profile)])==original_state[str(profile)], 'switch/probe changed original records, sync work or URK'
            # Independent important entries avoid the intentional daily-trivia append behavior.
            written=run('remember','Post-upgrade real inference '+account+' '+str(time.time_ns()),'--title','post-upgrade-'+account,'--importance','important','--force')
            assert written['summary'].get('id'),'real post-upgrade remember did not commit'
            # The durable write precedes derived indexing; compare stable snapshots after background completion.
            wait_index_ready()
            updated=snapshot(profile)
            updated_state=library_state(updated,recovery_factors[str(profile)])
            assert all(row in updated_state[0] for row in original_state[str(profile)][0]), 'remember changed an existing record'
            assert all(row in updated_state[1] for row in original_state[str(profile)][1]), 'remember changed existing sync work'
            assert updated_state[2]==expected_urks[str(profile)], 'remember changed the URK'
            original_state[str(profile)]=updated_state
            original[str(profile)]=updated
            assert run('recall','Post-upgrade real inference','--titles').get('items'),'post-upgrade remember could not be recalled'
            statuses.append({'account':account,'model_rows':rows})
        stress = None
        if args.resident_stress:
            import concurrent.futures, contextlib, psutil, threading
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}/api/health',headers={'X-Respire-Health':'runtime-v1'}), timeout=2) as response:
                health = json.load(response)
            owned = psutil.Process(health['pid'])
            if args.runtime_binary:
                observe_runtime(health)
            else:
                assert '--runtime-internal' in owned.cmdline(), 'stress must target its owned runtime'
            resource_members=None
            resource_members_checked=None
            def total_memory(refresh_members=True):
                global resource_members, resource_members_checked
                if refresh_members:
                    # Keep the original all-descendant audit. Continuous RSS
                    # sampling must not repeatedly scan the entire OS PID map.
                    resource_members=[owned,*owned.children(recursive=True)]
                    resource_members_checked=time.monotonic()
                members=resource_members
                memories=[member.memory_info() for member in members]
                return sum(memory.rss for memory in memories),sum(getattr(memory,'private',0) or 0 for memory in memories)
            baseline_rss,baseline_private=total_memory()
            samples = []
            observer_errors=[]
            timings = []
            body = 'resident stress query ' + 'background indexing and foreground retrieval '.join(['sample'] * 110)
            def timed(command, timeout=120, cancel=None):
                started = time.monotonic()
                try:
                    envelope = run(*command, timeout=timeout,cancel=cancel)
                except FixtureCancelled:
                    raise
                except Exception as error:
                    raise RuntimeError('stress '+command[0]+' failed after '+str(round(time.monotonic()-started,3))+'s: '+str(error)) from error
                assert envelope['status'] in ['ok', 'warn'], command[0]
                return command[0], time.monotonic() - started, envelope
            def probe_recall(timeout, cancel):
                command, elapsed, envelope = timed(['recall','Real account return fixture','--titles','--no-related'], timeout=timeout,cancel=cancel)
                assert envelope.get('items'), 'foreground overlap probe lost the indexed seed'
                return {'command':command,'seconds':elapsed,**envelope['_fixture_timing']}
            overlap = ForegroundOverlapProbe(probe_recall)
            fixed_workload_completed = None
            def sample_health(check_boundary=True):
                overlap.check()
                if check_boundary and observer_errors:
                    raise RuntimeError('continuous health observer failed: '+str(observer_errors))
                sample_started=time.monotonic()
                sample_unix=time.time()
                with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}/api/health',headers={'X-Respire-Health':'runtime-v1'}), timeout=2) as response:
                    current = json.load(response)
                health_completed=time.monotonic()
                assert current['pid'] == owned.pid, 'stress changed runtime ownership'
                inference = current.get('inference', {})
                overlap.observe(inference)
                rss,private=total_memory(refresh_members=check_boundary)
                memory_completed=time.monotonic()
                if check_boundary and args.expect_supervised_worker: checked_worker(current)
                samples.append({'rss':rss,'private':private,
                    'started_unix':sample_unix,'started_monotonic':sample_started,
                    'health_completed_monotonic':health_completed,
                    'health_seconds':health_completed-sample_started,
                    'memory_seconds':memory_completed-health_completed,
                    'boundary_seconds':time.monotonic()-memory_completed,
                    'membership_age_seconds':time.monotonic()-resource_members_checked,
                    'boundary_checked':check_boundary,
                    'retrieval_index':current.get('retrieval_index',{}),'inference':inference,
                    'foreground':inference.get('foreground',{}),'background':inference.get('background',{})})
            @contextlib.contextmanager
            def observed_pool():
                stopped=threading.Event()
                def observe():
                    try:
                        while not stopped.is_set():
                            # Retain every original boundary check in the main
                            # loop. Handle inspection must not starve concurrent
                            # HTTP responsiveness/lane/resource observations.
                            sample_health(check_boundary=False)
                            stopped.wait(.02)
                    except Exception as error: observer_errors.append(str(error))
                observer=threading.Thread(target=observe,name='resident-health-observer',daemon=True)
                observer.start()
                # Core lane telemetry is a 250 ms heartbeat, not a fresh native
                # sample on each HTTP poll. Model checksums/preparation can also
                # outlast the fixed CLI burst. Keep bounded real foreground work
                # available throughout preparation; never substitute queued work
                # or separate foreground/background observations for overlap.
                overlap.start()
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=18) as pool:
                        yield pool
                finally:
                    try:
                        overlap.close(cancel_pending=sys.exc_info()[0] is not None)
                    finally:
                        stopped.set()
                        observer.join(timeout=3)
                        # Persist evidence even when a deadline, client, or
                        # boundary assertion fails before final metrics exist.
                        (BASE/'resident-stress-metrics.json').write_text(json.dumps({
                            'passed':False,'requests':len(timings),'timings':timings,'samples':samples,
                            'overlap_probe':{'deadline_seconds':120,'max_in_flight':2,'timings':overlap.calls,
                                'errors':[str(error) for error in overlap.errors]},
                            'fixed_workload_completed_monotonic':fixed_workload_completed,
                            'observer_errors':observer_errors},indent=2),encoding='utf-8')
                        assert not observer.is_alive(),'continuous health observer did not stop'
                        assert not observer_errors,'continuous health observer failed: '+str(observer_errors)
            with observed_pool() as pool:
                print('resident phase: concurrent writes',flush=True)
                batch_deadline=time.monotonic()+120*2+10
                writes = [pool.submit(timed, ['remember', body, '--title', 'stress-'+str(i),
                    '--importance', 'important', '--force']) for i in range(28)]
                while any(not future.done() for future in writes):
                    assert time.monotonic()<batch_deadline,'resident write batch exceeded command deadlines'
                    sample_health()
                    time.sleep(.02)
                created = []
                for future in writes:
                    command, elapsed, envelope = future.result()
                    assert envelope['summary'].get('index_state') == 'pending', 'remember waited for derived indexing'
                    created.append(envelope['summary']['id'])
                    timings.append({'command':command,'seconds':elapsed,**envelope['_fixture_timing']})
                # Retrieval quality evaluation must use the same pending-aware
                # resident path as recall, without requiring derived artifacts.
                eval_file = BASE / 'resident-stress-eval.jsonl'
                bench_file = BASE / 'resident-stress-bench.json'
                eval_file.write_text(json.dumps({'query':'resident stress query','expect':created})+'\n',encoding='utf-8')
                run('bench','run',str(eval_file),'--save',str(bench_file))
                bench_report = json.loads(bench_file.read_text(encoding='utf-8'))
                # The worker can finish first; the controlled CLI unit fixture
                # separately proves the all-pending retrieval contract.
                assert 0 <= int(bench_report['params']['index_pending']) <= bench_report['n_entries'], 'invalid pending count'
                assert bench_report['metrics']['hitk'] == 1, 'pending-aware benchmark lost the expected source'
                run('bench','run',str(eval_file),'--baseline',str(bench_file))
                # A healthy owner must serve reads even while another process
                # holds the lifecycle gate for startup/replacement decisions.
                lifecycle = sqlite3.connect(main/'runtime/takeover/lock.db', timeout=2)
                try:
                    lifecycle.execute('BEGIN EXCLUSIVE')
                    command, elapsed, envelope = timed(['show', created[0]])
                    assert elapsed < 5, 'warm request acquired the lifecycle gate'
                finally:
                    lifecycle.rollback()
                    lifecycle.close()
                work = []
                print('resident phase: concurrent recall/show/update',flush=True)
                batch_deadline=time.monotonic()+120*5+10
                for i in range(28):
                    work.append(pool.submit(timed, ['recall','resident stress query','--titles','--no-related']))
                    work.append(pool.submit(timed, ['show',created[i]]))
                    if i < 16:
                        work.append(pool.submit(timed, ['update',created[i],'--title','updated-stress-'+str(i)]))
                work.append(pool.submit(timed, ['remember','concurrent trivial write','--importance','trivial']))
                while any(not future.done() for future in work):
                    assert time.monotonic()<batch_deadline,'resident mixed batch exceeded command deadlines'
                    sample_health()
                    time.sleep(.02)
                for future in work:
                    command, elapsed, envelope = future.result()
                    if command == 'recall':
                        assert envelope.get('items'), 'pending or indexed stress data was not recalled'
                    timings.append({'command':command,'seconds':elapsed,**envelope['_fixture_timing']})
                fixed_workload_completed = time.monotonic()
                while not overlap.observed.is_set():
                    sample_health()
                    time.sleep(.02)
            overlap_details = {'deadline_seconds':120,'max_in_flight':2,'timings':overlap.calls,
                'started_monotonic':overlap.started,
                'fixed_workload_completed_monotonic':fixed_workload_completed,
                'first_background_active_monotonic':min((sample['health_completed_monotonic'] for sample in samples if sample['background'].get('active')),default=None),
                'both_active_during_fixed_workload':any(sample['health_completed_monotonic'] <= fixed_workload_completed
                    and sample['foreground'].get('active') and sample['background'].get('active') for sample in samples)}
            metrics = {'passed':False,'requests':len(timings),'timings':timings,
                'overlap_probe':overlap_details,
                'rss_before':baseline_rss,'rss_peak':max(sample['rss'] for sample in samples),
                'resource_scope':'owned host and all descendants',
                'private_before':baseline_private,
                'private_peak':max((sample['private'] or 0) for sample in samples),
                'both_lanes_observed':any(sample['foreground'].get('active') and sample['background'].get('active') for sample in samples),
                'samples':samples}
            (BASE/'resident-stress-metrics.json').write_text(json.dumps(metrics,indent=2),encoding='utf-8')
            assert metrics['both_lanes_observed'],'concurrent foreground/background activity was not observed'
            # This fixture submits 28 long documents and 16 content-bearing edits;
            # its background batch is larger than the initial account preparation.
            print('resident phase: final index drain (900s)',flush=True)
            wait_index_ready(timeout=900)
            database = main / 'rsrs.db'
            if not database.exists(): database = main / 'onememory.db'
            with sqlite3.connect(database) as database_connection:
                missing = database_connection.execute(
                    'SELECT COUNT(*) FROM memories m WHERE deleted=0 AND NOT EXISTS '
                    '(SELECT 1 FROM core_artifacts a WHERE a.memory_id=m.id AND a.source=m.ciphertext)').fetchone()[0]
            assert missing == 0, 'background index did not catch up with edited sources'
            light = [entry['seconds'] for entry in timings if entry['command'] == 'show']
            assert max(light) < 5, 'lightweight reads were blocked by inference or background work'
            stress = {'passed':True,'requests':len(timings),'background_source_checks':True,
                'overlap_probe':overlap_details,
                'show_max_seconds':max(light),'timings':timings,'rss_before':baseline_rss,
                'resource_scope':'owned host and all descendants',
                'rss_peak':max(sample['rss'] for sample in samples),
                'private_before':baseline_private,
                'private_peak':max((sample['private'] or 0) for sample in samples),
                'both_lanes_observed':any(sample['foreground'].get('active') and sample['background'].get('active') for sample in samples),
                'samples':samples}
            (BASE/'resident-stress-metrics.json').write_text(json.dumps(stress,indent=2),encoding='utf-8')
        normal_reopen_checked=False
        if database_upgrade:
            before_close={str(profile):library_state(snapshot(profile),recovery_factors[str(profile)]) for profile in [main,alternate]}
            closing_owner=observe_runtime()
            owned=psutil.Process(closing_owner['pid'])
            retired=[(owned.pid,owned.create_time()), *[(child.pid,child.create_time()) for child in owned.children(recursive=True)]]
            if args.client2_binary:
                run_client2('stop')
            else:
                stopped=captured_run([str(binary),'--runtime-internal','--stop'],env=env,timeout=50)
                assert stopped.returncode==0, 'normal database owner stop failed'
            confirm_workers_exited(retired)
            assert {str(profile):library_state(snapshot(profile),recovery_factors[str(profile)]) for profile in [main,alternate]}==before_close, 'normal close changed records, sync work or URK'
            if args.client2_binary:
                run_client2('start')
                assert observe_runtime()['store_ready'], 'Client2 restart did not unlock the historical database'
            for account,profile in [('main',main),('alternate',alternate),('main',main)]:
                run('account','use',account)
                wait_index_ready()
                reopened=observe_runtime()
                assert reopened['instance_id']!=closing_owner['instance_id'], 'database reopen reused the stopped owner'
                assert run('recall','Real account return fixture','--titles').get('items'), 'reopened database lost historical recall'
                assert run('recall','Post-upgrade real inference','--titles').get('items'), 'reopened database lost post-upgrade recall'
                assert library_state(snapshot(profile),recovery_factors[str(profile)])==before_close[str(profile)], 'normal reopen changed records, sync work or URK'
            normal_reopen_checked=True
        restart_checked=False
        if args.expect_in_process or args.expect_supervised_worker:
            import psutil
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}/api/health',headers={'X-Respire-Health':'runtime-v1'}),timeout=2) as response:
                health=json.load(response)
            owned=psutil.Process(health['pid'])
            retired_workers=[checked_worker(health)] if args.expect_supervised_worker else []
            if args.runtime_binary:
                observe_runtime(health)
                assert same_existing_path(owned.exe(),args.runtime_binary)
            else:
                assert pathlib.Path(owned.exe()).name.lower() in ['rsrs','rsrs.exe']
                assert '--runtime-internal' in owned.cmdline(),'only the isolated runtime may be suspended'
            before_restart={str(profile):library_state(snapshot(profile),recovery_factors[str(profile)]) for profile in [main,alternate]}
            config_before=(main/'client.json').read_bytes()
            endpoint_before=(main/'runtime/endpoint.json').read_bytes()
            token_path=main/'runtime/token'
            token_before=token_path.read_bytes() if token_path.is_file() else None
            registration_path=main/'runtime/autostart/registration.json'
            registration_before=registration_path.read_bytes() if registration_path.is_file() else None
            owned_birth=owned.create_time()
            try:
                owned.suspend()
                restarted=run('restart','--timeout','1',allow_failure=bool(args.runtime_binary))
                if args.runtime_binary:
                    assert restarted.get('status')=='fail','restart replaced a suspended live owner'
                    assert psutil.Process(owned.pid).create_time()==owned_birth and owned.is_running()
                    assert process_start_id(owned.pid)==health['process_start_id']
                    assert (main/'client.json').read_bytes()==config_before
                    assert (main/'runtime/endpoint.json').read_bytes()==endpoint_before
                    assert (token_path.read_bytes() if token_path.is_file() else None)==token_before
                    assert (registration_path.read_bytes() if registration_path.is_file() else None)==registration_before
            finally:
                if owned.is_running() and owned.create_time()==owned_birth:
                    if args.runtime_binary: assert process_start_id(owned.pid)==health['process_start_id']
                    owned.resume()
            if args.runtime_binary:
                assert {str(profile):library_state(snapshot(profile),recovery_factors[str(profile)]) for profile in [main,alternate]}==before_restart
                resumed=observe_runtime()
                assert (resumed['pid'],resumed['process_start_id'],resumed['instance_id'])==(
                    health['pid'],health['process_start_id'],health['instance_id'])
                live_owner_restart_rejected=True
                restarted=run('restart','--timeout','10')
                assert restarted['summary']['forced'] is False,restarted
            else:
                assert restarted['summary']['forced'] is True,restarted
            assert restarted['summary']['stopped_pid']==health['pid'],restarted
            assert restarted['summary']['pid']!=health['pid'],restarted
            confirm_workers_exited(retired_workers)
            if args.runtime_binary:
                confirm_workers_exited([(owned.pid,owned_birth)])
                replacement=observe_runtime()
                assert replacement['pid']==restarted['summary']['pid']
                assert (replacement['pid'],replacement['process_start_id'])!=(health['pid'],health['process_start_id'])
                assert replacement['instance_id']!=health['instance_id']
                assert replacement['image_sha256']==health['image_sha256']==args.runtime_sha256
            assert same_existing_path(restarted['summary']['data_dir'],main),restarted
            assert (main/'client.json').read_bytes()==config_before,'restart changed the account or API configuration'
            assert {str(profile):library_state(snapshot(profile),recovery_factors[str(profile)]) for profile in [main,alternate]}==before_restart,'restart changed original records, sync work or URK'
            if args.seed_binary:
                for account,profile in [('alternate',alternate),('main',main)]:
                    if sys.platform=='darwin':
                        run('account','use',account)
                        wait_index_ready()
                    verify_fixture_custody(profile,keys,custody_slots[str(profile)],expected_urks[str(profile)],binary,env)
                assert (main/'client.json').read_bytes()==config_before, 'post-restart custody changed account routing'
                assert {str(profile):library_state(snapshot(profile),recovery_factors[str(profile)]) for profile in [main,alternate]}==before_restart, 'post-restart custody changed original library state'
                if sys.platform=='darwin' and args.runtime_binary:
                    replacement=observe_runtime()
            run('model','probe','--model','m3')
            assert run('recall','Real account return fixture','--titles').get('items')
            if args.runtime_binary:
                ready=observe_runtime()
                assert (ready['pid'],ready['process_start_id'],ready['instance_id'])==(
                    replacement['pid'],replacement['process_start_id'],replacement['instance_id'])
            if args.expect_supervised_worker:
                with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}/api/health',headers={'X-Respire-Health':'runtime-v1'}),timeout=2) as response:
                    checked_worker(json.load(response))
            restart_checked=True
        if args.seed_binary:
            assert set(custody_receipts)==set(custody_slots) and len(custody_receipts)==2, 'host custody evidence missing for a historical account'
        checkpoint_evidence = None
        if args.database_dev_checkpoint:
            for profile in [main, alternate]:
                current = snapshot(profile)
                state = database_checkpoint_state(profile, args.database_dev_checkpoint,
                    current, library_state(current, recovery_factors[str(profile)])[0])
                assert_database_checkpoint_preserved(checkpoint_before[str(profile)], state)
            checkpoint_evidence = {'tag': args.database_dev_checkpoint, 'special_state_seeded': True,
                'special_state_preserved': True, 'verified_accounts': ['main', 'alternate']}
        if database_upgrade:
            # All offline evidence above is complete before any account/network changes.
            network_smoke=vault_crypto.Smoke(SimpleNamespace(root=root/'historical-sync', binary=binary,
                binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                source_sha=os.environ['CLI_SHA'], version=os.environ['CLI_VERSION']))
            network_smoke.keys=keys
            network_smoke.model=CACHE
            network_evidence=network_smoke.historical_database_sync(env, expected_urks[str(main)], code,
                original_state[str(main)][0])
            assert library_state(snapshot(alternate),recovery_factors[str(alternate)])==original_state[str(alternate)], 'network stage changed the offline alternate library'
            if args.database_dev_checkpoint:
                current=snapshot(main)
                active=[(row[0],vault_crypto.decrypt_content(expected_urks[str(main)],row[1],row[2]),row[3],row[4])
                    for row in current[0][0] if row[1]]
                state=database_checkpoint_state(main,args.database_dev_checkpoint,current,active)
                before=checkpoint_before[str(main)]
                if before['kind']=='legacy_relation_payload':
                    live_ids={row[0] for row in original_state[str(main)][0] if not row[3]}
                    before={**before,'links':[row for row in before['links'] if row[0] in live_ids]}
                assert_database_checkpoint_preserved(before,state)
                checkpoint_evidence['post_sync_special_state_preserved']=True
                checkpoint_evidence['sync_verified_accounts']=['main']
            assert run('recall','Historical reverse synchronization','--titles').get('items'), 'verified source owner lost reverse marker'
        seed_identity = ({'seed_source': 'v' + seed_version,
                          'seed_sha256': hashlib.sha256(pathlib.Path(args.seed_binary).read_bytes()).hexdigest()}
                         if args.seed_source else {})
        reports.append({'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'binary':str(binary),'passed':True,
            'real_model':True,'model_file':args.model_file,'engine':'cpu','in_process_checked':args.expect_in_process,
            'supervised_worker_checked':args.expect_supervised_worker,'owned_worker_identities':worker_identities,
            'global_engine_preserved':not database_upgrade,'distinct_vault_keys':True,'sequence':statuses,
            'coverage_scope':'historical-database' if database_upgrade else 'current-host',
            'host_checks_delegated_to':'resident-concurrency' if database_upgrade else None,
            'normal_reopen_checked':normal_reopen_checked,'runtime_artifact_reused':runtime_artifact_reused,
            'stale_endpoint_archived':stale_endpoint_archived,
            'client2_sha256':args.client2_sha256,
            'client2_native_credential_migration':bool(args.client2_binary),
            'original_records_preserved':True,'original_sync_work_preserved':True,'urk_preserved':True,
            'old_records_decrypted':True,'post_upgrade_recall_checked':True,
            'encrypted_tombstones_preserved':bool(args.seed_binary),
            'post_upgrade_sync_checked':False,
            'post_upgrade_sync':network_evidence,
            'seed_vault_versions':seed_vault_versions,
            'database_dev_checkpoint':checkpoint_evidence,
            'host_credential_custody':{'required':bool(args.seed_binary),'verified_accounts':list(custody_receipts.values())},
            'historical_credential_migration_actor':'fixture' if args.seed_binary else None,
            'resident_stress':stress,
            'upgrade_contract':'standalone-v1' if args.runtime_binary else 'legacy-shim-v1',
            'source_rpc_checked':source_rpc_checked,'legacy_handoff_actor':legacy_handoff_actor,
            'runtime_installed_after_legacy_data':runtime_installed_after_legacy_data,
            'live_owner_restart_rejected':live_owner_restart_rejected,
            'forced_restart_checked':restart_checked and not bool(args.runtime_binary),
            'safe_restart_checked':restart_checked and bool(args.runtime_binary),
            'legacy_client_rejected':legacy_client_rejected,'old_rpc_checked':old_rpc_checked,
            'old_rpc_authenticated':old_rpc_authenticated,'initial_generation_changes':generation_changes,'fixture':str(root),
            **seed_identity,**runtime_report(args,True)})
    except Exception as error:
        reports.append({'binary':str(binary),'passed':False,'error':str(error)[:2000],
            **({'provider_account_switch':provider_account_switch} if provider_account_switch is not None else {}),
            **({'runtime_stop_failure':stop_failure} if stop_failure is not None else {})})
        (BASE/'real-account-return-verification.json').write_text(json.dumps(reports,indent=2),encoding='utf-8')
        raise
    finally:
        cleanup_errors=[]
        try:
            if inspector is not None: inspector.close()
        except Exception as error: cleanup_errors.append('inspector: '+str(error))
        try:
            if components_started:
                stopped=captured_run([str(binary),'--runtime-internal','--stop'],env=env,timeout=50)
                assert stopped.returncode==0,'owned runtime stop failed'
        except Exception as error: cleanup_errors.append('runtime: '+str(error))
        try:
            if args.expect_supervised_worker: confirm_workers_exited(worker_identities)
        except Exception as error: cleanup_errors.append('worker reap: '+str(error))
        try:
            if old_runtime is not None and old_runtime.poll() is None:
                old_runtime.terminate(); old_runtime.wait(timeout=15)
        except Exception as error: cleanup_errors.append('old runtime: '+str(error))
        if network_smoke is not None:
            try:
                network_smoke.cleanup()
                reports[-1]['cloud_cleanup']=network_smoke.report['cloud_cleanup']
                assert reports[-1]['cloud_cleanup']['passed'] is True, 'historical sync cloud cleanup failed'
            except Exception as error:
                cleanup_errors.append('cloud: '+str(error))
            reports[-1]['post_upgrade_sync_diagnostic']={field:network_smoke.report[field]
                for field in ('stage','server_sha','cli_failure','provider_observation',
                    'identity_preparation') if field in network_smoke.report}
        if keys is not None:
            try:
                expected_slots=len(keys.entries) if network_smoke is not None else None
                reports[-1]['native_credential_cleanup']=keys.cleanup()
                provider=reports[-1]['native_credential_cleanup'].get('provider_daemon')
                if network_smoke is not None and provider is not None and (provider.get('started') is not True
                        or provider.get('exit_code_at_cleanup_start') is not None):
                    reports[-1]['native_credential_cleanup'].update(passed=False,
                        failure_code='original_provider_not_running_at_cleanup')
                assert reports[-1]['native_credential_cleanup'].get('passed') is True \
                    and not reports[-1]['native_credential_cleanup'].get('remaining_entries'), 'native credential cleanup failed'
                custody=reports[-1].get('host_credential_custody')
                if custody is not None and custody['required']:
                    if expected_slots is None:
                        expected_slots=sum(len(plan[2]) for plan in custody_slots.values())
                    assert len(reports[-1]['native_credential_cleanup']['events'])==expected_slots, 'custody cleanup omitted an owned slot'
                    custody['cleanup_passed']=True
            except Exception as error:
                reports[-1].setdefault('native_credential_cleanup',
                    {'passed':False,'failure_code':type(error).__name__})
                cleanup_errors.append('native credentials: '+str(error))
        if cleanup_errors:
            reports[-1]['passed']=False
            reports[-1]['cleanup_errors']=cleanup_errors
        if network_evidence and reports[-1]['passed']:
            reports[-1]['post_upgrade_sync_checked']=(same_existing_path(network_evidence.get('profile'),main)
                and all(network_evidence.get(field) is True for field in ('original_urk_preserved',
                    'existing_keys_registered','source_push','independent_pull_decrypted','reverse_marker_source_pull',
                    'original_active_preserved','tombstones_propagated','pending_work_acknowledged'))
                and reports[-1]['cloud_cleanup']['passed'] is True
                and reports[-1]['native_credential_cleanup']['passed'] is True)
        reports[-1].update(runtime_report(args,reports[-1]['passed']))
        if args.runtime_binary and not reports[-1]['standalone_runtime_evidence']:
            reports[-1]['passed']=False
        (BASE/'real-account-return-verification.json').write_text(json.dumps(reports,indent=2),encoding='utf-8')
        if cleanup_errors and sys.exc_info()[0] is None:
            raise RuntimeError('fixture cleanup failed: '+str(cleanup_errors))
    assert reports[-1]['passed'], 'fixture evidence incomplete'
    print('PASS '+str(binary)+': main -> alternate -> main; real CPU inference; original records decrypted and URKs preserved',flush=True)
(BASE/'real-account-return-verification.json').write_text(json.dumps(reports,indent=2),encoding='utf-8')
