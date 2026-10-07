"""Read-only real M3 cache; disposable profiles and owned runtime port only."""
import argparse, hashlib, hmac, json, os, pathlib, secrets, socket, sqlite3, subprocess, sys, time, urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

parser=argparse.ArgumentParser()
parser.add_argument('--binary',action='append',required=True)
parser.add_argument('--model-dir',required=True)
parser.add_argument('--model-file',choices=['model_quantized.onnx','model_fp16.onnx'],default='model_quantized.onnx')
parser.add_argument('--legacy-model-dir',help='Read-only baseline cache containing real FP16 and quantized files')
parser.add_argument('--output-dir',required=True)
parser.add_argument('--expect-in-process',action='store_true')
parser.add_argument('--seed-binary',help='Create both libraries with this published older binary, then upgrade its running runtime')
args=parser.parse_args()
BASE=pathlib.Path(args.output_dir).resolve()
BASE.mkdir(parents=True,exist_ok=True)
CACHE=pathlib.Path(args.model_dir).resolve()
BINARIES=[pathlib.Path(path).resolve() for path in args.binary]
MODEL_HASHES={'model_quantized.onnx':'0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d',
    'model_fp16.onnx':'4f1a646a3d4f39985589e9991a717044ede8278617fe55e3d246838bc05055e9'}
def verify_model(cache,model):
    for name,expected in [('tokenizer.json','6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790'),('onnx/'+model,MODEL_HASHES[model])]:
        with (cache/name).open('rb') as stream: assert hashlib.file_digest(stream,'sha256').hexdigest()==expected
verify_model(CACHE,args.model_file)
LEGACY_CACHE=pathlib.Path(args.legacy_model_dir).resolve() if args.legacy_model_dir else CACHE
if args.seed_binary:
    verify_model(LEGACY_CACHE,'model_fp16.onnx')
    if args.model_file=='model_quantized.onnx': verify_model(LEGACY_CACHE,'model_quantized.onnx')
reports = []
for binary in BINARIES:
    root = BASE / ('account-return-real-' + str(time.time_ns()))
    if os.name == 'posix' and args.seed_binary:
        # Historical runtimes bind rpc.sock under the library. A nested CI
        # report directory exceeds Unix socket path limits; keep the owned
        # fixture in a short workspace directory and retain reports in BASE.
        root = pathlib.Path.cwd() / ('rsrs-up-' + secrets.token_hex(6))
    main = root / '.rsrs'
    alternate = main / 'accounts/alternate'
    alternate.mkdir(parents=True)
    entropy = secrets.token_bytes(18)
    code = 'A3-' + '-'.join(entropy.hex().upper()[i:i+6] for i in range(0,36,6))
    for profile in [main, alternate]:
        salt,nonce,urk=secrets.token_bytes(16),secrets.token_bytes(12),secrets.token_bytes(32)
        kek=hmac.new(hmac.new(salt,entropy,hashlib.sha256).digest(),b'onememory:kek:v4\x01',hashlib.sha256).digest()
        session=json.dumps({'user':'fixture-'+str(time.time_ns()),'vault_version':4,'kdf_salt':salt.hex(),'wrapped_urk':AESGCM(kek).encrypt(nonce,urk,None).hex(),'urk_nonce':nonce.hex()}).encode()
        (profile/'session.json').write_bytes(session)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0)); port = listener.getsockname()[1]
    env = os.environ.copy()
    for suffix in ['CLIENT_ONLY','NO_AUTOSTART','RUNTIME_WORKER','CORE_TEST_MODE','RPC_TOKEN','ENGINE','ADDR','TOKEN','JSON','ORT_DEBUG']:
        for prefix in ['RSRS_', 'ONEMEMORY_', 'RESPIRE_']:
            env.pop(prefix + suffix,None)
    env.update(HOME=str(root), USERPROFILE=str(root), RSRS_DATA_DIR=str(main), RSRS_RPC_PORT=str(port),
        RSRS_SUPER=code,RSRS_NO_AUTOSYNC='1',RSRS_UPDATE_CHECK='0',RSRS_M3_DIR=str(CACHE))
    seed_env={**env,'RSRS_M3_DIR':str(LEGACY_CACHE)}
    # Historical artifacts predate RSRS_*; keep their inputs explicit and
    # isolated instead of accidentally testing the operator's default library.
    for key, value in list(seed_env.items()):
        if key.startswith(('RSRS_', 'ONEMEMORY_', 'RESPIRE_')):
            seed_env['ONEMEMORY_' + key[5:]] = value
    def run(*args, allow_failure=False):
        result = subprocess.run([str(binary),'--json',*args],env=env,capture_output=True,timeout=120)
        if result.returncode and not allow_failure: raise RuntimeError(result.stdout.decode(errors='replace')+result.stderr.decode(errors='replace'))
        return json.loads(result.stdout)
    def snapshot(profile):
        database = profile/'rsrs.db'
        if not database.exists(): database = profile/'onememory.db'
        with sqlite3.connect(database) as db:
            rows = [db.execute(query).fetchall() for query in ['SELECT id,ciphertext,nonce,dirty,deleted FROM memories ORDER BY id',
                'SELECT * FROM sync_outbox ORDER BY seq','SELECT * FROM core_artifacts ORDER BY memory_id,model']]
        artifacts = sorted((path.name,hashlib.sha256(path.read_bytes()).hexdigest()) for path in (profile/'core-index').iterdir())
        return (rows,artifacts,(profile/'session.json').read_bytes())
    old_runtime=None
    old_rpc_checked=False
    old_rpc_authenticated=False
    public_config={'addr':'https://fixture.invalid','autosync':False,'custom':'preserve-upgrade-fixture'}
    def select(profile):
        (main/'client.json').write_text(json.dumps({**public_config,'data_dir':str(profile)}),encoding='utf-8')
    try:
        run('--direct','model','engine','cpu')
        global_engine=(main/'inference.json').read_bytes()
        for profile in [main,alternate]:
            select(profile)
            if args.seed_binary:
                for command in [('model','activate','m3'),('remember','Real account return fixture '+profile.name,'--title',profile.name,'--importance','important','--force')]:
                    seeded=subprocess.run([str(pathlib.Path(args.seed_binary).resolve()),'--json','--direct',*command],env=seed_env,capture_output=True,timeout=180)
                    assert seeded.returncode==0,seeded.stdout.decode(errors='replace')+seeded.stderr.decode(errors='replace')
            else:
                run('--direct','remember','Real account return fixture '+profile.name,'--title',profile.name,'--importance','important','--force')
        original = {str(profile):snapshot(profile) for profile in [main,alternate]}
        select(main)
        if args.seed_binary:
            log=(root/'old-runtime.log').open('wb')
            web_help=subprocess.check_output([args.seed_binary,'web','--help'],text=True,encoding='utf-8',timeout=30)
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
            # The new client must exercise the old HTTP RPC, not only health/stop.
            # Client-only status is read-only and cannot take over the old runtime.
            original_token=token.read_bytes() if token.is_file() else None
            old_status=run('--client-only','status')
            assert old_status.get('status')=='ok','new client could not read the old runtime through HTTP RPC'
            assert old_runtime.poll() is None,'client-only RPC replaced or stopped the old runtime'
            request=urllib.request.Request(f'http://127.0.0.1:{port}/api/health',headers=headers)
            with urllib.request.urlopen(request,timeout=2) as response: after_rpc=json.load(response)
            assert after_rpc['pid']==old_runtime.pid,'client-only RPC changed runtime ownership'
            assert (token.read_bytes() if token.is_file() else None)==original_token,'client-only RPC changed the old token file'
            old_rpc_checked=True
            old_rpc_authenticated=bool(original_token and original_token.strip())
        statuses=[]
        visited=set()
        generation_changes={}
        for account, profile in [('main',main),('alternate',alternate),('main',main)]:
            run('account','use',account)
            if old_runtime is not None:
                assert old_runtime.wait(timeout=20)==0,'old runtime did not exit gracefully'
            assert run('model','engine')['summary']['engine']=='cpu'
            assert (main/'inference.json').read_bytes()==global_engine
            assert not (alternate/'inference.json').exists()
            # A real model change may rebuild derived indexes once; never source data.
            deadline=time.monotonic()+180
            while True:
                doctor=run('doctor',allow_failure=True)
                rows={item['name']:item for item in doctor['items'] if item['name'] in ['embedder','model index']}
                if len(rows)==2 and all(item['status']=='ok' for item in rows.values()): break
                assert time.monotonic()<deadline,rows
                time.sleep(.25)
            if args.seed_binary and str(profile) not in visited:
                current=snapshot(profile)
                baseline=original[str(profile)]
                assert current[0][:2]==baseline[0][:2] and current[2]==baseline[2],'model migration changed ciphertext, sync work or keys'
                generation_changes[str(profile)]=current[0][2]!=baseline[0][2] or current[1]!=baseline[1]
                original[str(profile)]=current
            visited.add(str(profile))
            if args.expect_in_process:
                import psutil
                pending=subprocess.Popen([str(binary),'--json','model','probe','--model','m3'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                checks=0
                deadline=time.monotonic()+120
                try:
                    while pending.poll() is None:
                        assert time.monotonic()<deadline,'native probe exceeded the acceptance deadline'
                        start=time.monotonic()
                        with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health',timeout=2) as response:
                            health=json.load(response)
                        assert time.monotonic()-start < 2,'health blocked behind native inference'
                        children=psutil.Process(health['pid']).children(recursive=True)
                        # Windows may attach its console host; it is not an inference worker.
                        children=[child for child in children if not (sys.platform=='win32' and child.name().lower()=='conhost.exe')]
                        assert not children, 'runtime spawned an inference child: '+str([child.name() for child in children])
                        checks+=1
                        time.sleep(.05)
                    stdout,stderr=pending.communicate(timeout=120)
                    assert pending.returncode==0,stdout.decode(errors='replace')+stderr.decode(errors='replace')
                    assert checks>0,'native inference responsiveness was not exercised'
                finally:
                    if pending.poll() is None:
                        pending.kill(); pending.communicate()
            else:
                run('model','probe','--model','m3')
            recalled=run('recall','Real account return fixture','--titles')
            assert recalled.get('items'),'real recall returned no seeded entry'
            doctor=run('doctor',allow_failure=True)
            rows={item['name']:item for item in doctor['items'] if item['name'] in ['embedder','model index']}
            assert len(rows)==2 and all(item['status']=='ok' for item in rows.values()),rows
            assert pathlib.Path(json.loads((main/'client.json').read_text())['data_dir'])==profile
            config=json.loads((main/'client.json').read_text())
            assert all(config.get(key)==value for key,value in public_config.items()),'upgrade/switch changed public API settings'
            assert snapshot(profile)==original[str(profile)],'switch/probe changed source data or rebuilt existing index'
            # Independent important entries avoid the intentional daily-trivia append behavior.
            written=run('remember','Post-upgrade real inference '+account+' '+str(time.time_ns()),'--title','post-upgrade-'+account,'--importance','important','--force')
            assert written['summary'].get('id'),'real post-upgrade remember did not commit'
            updated=snapshot(profile)
            assert all(row in updated[0][0] for row in original[str(profile)][0][0]),'remember changed an existing ciphertext'
            assert all(row in updated[0][1] for row in original[str(profile)][0][1]),'remember changed existing sync work'
            assert all(row in updated[0][2] for row in original[str(profile)][0][2]),'remember changed a compatible existing index'
            assert updated[2]==original[str(profile)][2],'remember changed vault keys'
            original[str(profile)]=updated
            assert run('recall','Post-upgrade real inference','--titles').get('items'),'post-upgrade remember could not be recalled'
            statuses.append({'account':account,'model_rows':rows})
        restart_checked=False
        if args.expect_in_process:
            import psutil
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health',timeout=2) as response:
                health=json.load(response)
            owned=psutil.Process(health['pid'])
            assert pathlib.Path(owned.exe()).name.lower() in ['rsrs','rsrs.exe']
            assert '--runtime-internal' in owned.cmdline(),'only the isolated runtime may be suspended'
            before_restart={str(profile):snapshot(profile) for profile in [main,alternate]}
            config_before=(main/'client.json').read_bytes()
            try:
                owned.suspend()
                restarted=run('restart','--timeout','1')
            finally:
                if owned.is_running():
                    owned.resume()
            assert restarted['summary']['forced'] is True,restarted
            assert restarted['summary']['stopped_pid']==health['pid'],restarted
            assert restarted['summary']['pid']!=health['pid'],restarted
            assert pathlib.Path(restarted['summary']['data_dir'])==main,restarted
            assert (main/'client.json').read_bytes()==config_before,'restart changed the account or API configuration'
            assert {str(profile):snapshot(profile) for profile in [main,alternate]}==before_restart,'restart changed source, key, sync or compatible index'
            run('model','probe','--model','m3')
            assert run('recall','Real account return fixture','--titles').get('items')
            restart_checked=True
        reports.append({'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'binary':str(binary),'passed':True,
            'real_model':True,'model_file':args.model_file,'engine':'cpu','in_process_checked':args.expect_in_process,
            'global_engine_preserved':True,'distinct_vault_keys':True,'sequence':statuses,'source_and_keys_unchanged':True,
            'compatible_index_reused':True,'forced_restart_checked':restart_checked,'old_rpc_checked':old_rpc_checked,
            'old_rpc_authenticated':old_rpc_authenticated,'initial_generation_changes':generation_changes,'fixture':str(root)})
        print('PASS '+str(binary)+': main -> alternate -> main; real CPU inference; compatible index reused after preparation',flush=True)
    except Exception as error:
        reports.append({'binary':str(binary),'passed':False,'error':str(error)[:2000]})
        raise
    finally:
        subprocess.run([str(binary),'--runtime-internal','--stop'],env=env,capture_output=True,timeout=50)
        if old_runtime is not None and old_runtime.poll() is None:
            old_runtime.terminate(); old_runtime.wait(timeout=15)
        (BASE/'real-account-return-verification.json').write_text(json.dumps(reports,indent=2),encoding='utf-8')
(BASE/'real-account-return-verification.json').write_text(json.dumps(reports,indent=2),encoding='utf-8')
