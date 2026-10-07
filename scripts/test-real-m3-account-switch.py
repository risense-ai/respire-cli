"""Read-only real M3 cache; disposable profiles and owned runtime port only."""
import argparse, hashlib, hmac, json, os, pathlib, secrets, socket, sqlite3, subprocess, sys, time, urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

parser=argparse.ArgumentParser()
parser.add_argument('--binary',action='append',required=True)
parser.add_argument('--model-dir',required=True)
parser.add_argument('--output-dir',required=True)
parser.add_argument('--expect-in-process',action='store_true')
parser.add_argument('--seed-binary',help='Create both libraries with this published older binary, then upgrade its running runtime')
args=parser.parse_args()
BASE=pathlib.Path(args.output_dir).resolve()
BASE.mkdir(parents=True,exist_ok=True)
CACHE=pathlib.Path(args.model_dir).resolve()
BINARIES=[pathlib.Path(path).resolve() for path in args.binary]
for name,expected in [('tokenizer.json','6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790'),('onnx/model_fp16.onnx','4f1a646a3d4f39985589e9991a717044ede8278617fe55e3d246838bc05055e9')]:
    with (CACHE/name).open('rb') as stream: assert hashlib.file_digest(stream,'sha256').hexdigest()==expected
reports = []
for binary in BINARIES:
    root = BASE / ('account-return-real-' + str(time.time_ns()))
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
    for key in ['ONEMEMORY_CLIENT_ONLY','ONEMEMORY_NO_AUTOSTART','ONEMEMORY_RUNTIME_WORKER','RESPIRE_CORE_TEST_MODE','ONEMEMORY_RPC_TOKEN','ONEMEMORY_ENGINE','ONEMEMORY_ADDR','ONEMEMORY_TOKEN','ONEMEMORY_JSON','ONEMEMORY_ORT_DEBUG']:
        env.pop(key,None)
    env.update(HOME=str(root), USERPROFILE=str(root), ONEMEMORY_DATA_DIR=str(main), ONEMEMORY_RPC_PORT=str(port),
        ONEMEMORY_SUPER=code,ONEMEMORY_NO_AUTOSYNC='1',ONEMEMORY_UPDATE_CHECK='0',ONEMEMORY_M3_DIR=str(CACHE))
    def run(*args, allow_failure=False):
        result = subprocess.run([str(binary),'--json',*args],env=env,capture_output=True,timeout=120)
        if result.returncode and not allow_failure: raise RuntimeError(result.stdout.decode(errors='replace')+result.stderr.decode(errors='replace'))
        return json.loads(result.stdout)
    def snapshot(profile):
        with sqlite3.connect(profile/'onememory.db') as db:
            rows = [db.execute(query).fetchall() for query in ['SELECT id,ciphertext,nonce,dirty,deleted FROM memories ORDER BY id',
                'SELECT * FROM sync_outbox ORDER BY seq','SELECT * FROM core_artifacts ORDER BY memory_id,model']]
        artifacts = sorted((path.name,hashlib.sha256(path.read_bytes()).hexdigest()) for path in (profile/'core-index').iterdir())
        return (rows,artifacts,(profile/'session.json').read_bytes())
    old_runtime=None
    public_config={'addr':'https://fixture.invalid','autosync':False,'custom':'preserve-upgrade-fixture'}
    def select(profile):
        (main/'client.json').write_text(json.dumps({**public_config,'data_dir':str(profile)}),encoding='utf-8')
    try:
        run('--direct','model','engine','cpu')
        global_engine=(main/'inference.json').read_bytes()
        for profile in [main,alternate]:
            select(profile)
            if args.seed_binary:
                for command in [('model','activate','m3'),('remember','Real account return fixture '+profile.name,'--title',profile.name,'--force')]:
                    seeded=subprocess.run([str(pathlib.Path(args.seed_binary).resolve()),'--json','--direct',*command],env=env,capture_output=True,timeout=180)
                    assert seeded.returncode==0,seeded.stdout.decode(errors='replace')+seeded.stderr.decode(errors='replace')
            else:
                run('--direct','remember','Real account return fixture '+profile.name,'--title',profile.name,'--force')
        original = {str(profile):snapshot(profile) for profile in [main,alternate]}
        select(main)
        if args.seed_binary:
            log=(root/'old-runtime.log').open('wb')
            web_help=subprocess.check_output([args.seed_binary,'web','--help'],text=True)
            runtime_args=['web','--internal','--no-open','--port',str(port)] if '--port' in web_help else ['--runtime-internal']
            old_runtime=subprocess.Popen([str(pathlib.Path(args.seed_binary).resolve()),*runtime_args],env=env,stdout=log,stderr=log)
            log.close()
            for attempt in range(200):
                assert old_runtime.poll() is None,'published old runtime exited before upgrade'
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
        statuses=[]
        for account, profile in [('main',main),('alternate',alternate),('main',main)]:
            run('account','use',account)
            if old_runtime is not None:
                assert old_runtime.wait(timeout=20)==0,'old runtime did not exit gracefully'
            assert run('model','engine')['summary']['engine']=='cpu'
            assert (main/'inference.json').read_bytes()==global_engine
            assert not (alternate/'inference.json').exists()
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
            written=run('remember','Post-upgrade real inference '+account+' '+str(time.time_ns()),'--title','post-upgrade-'+account,'--force')
            assert written['summary'].get('id'),'real post-upgrade remember did not commit'
            updated=snapshot(profile)
            assert all(row in updated[0][0] for row in original[str(profile)][0][0]),'remember changed an existing ciphertext'
            assert all(row in updated[0][1] for row in original[str(profile)][0][1]),'remember changed existing sync work'
            assert all(row in updated[0][2] for row in original[str(profile)][0][2]),'remember changed a compatible existing index'
            assert updated[2]==original[str(profile)][2],'remember changed vault keys'
            original[str(profile)]=updated
            assert run('recall','Post-upgrade real inference','--titles').get('items'),'post-upgrade remember could not be recalled'
            statuses.append({'account':account,'model_rows':rows})
        reports.append({'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'binary':str(binary),'passed':True,
            'real_model':True,'engine':'cpu','in_process_checked':args.expect_in_process,'global_engine_preserved':True,'distinct_vault_keys':True,'sequence':statuses,'index_source_and_keys_unchanged':True,'fixture':str(root)})
        print('PASS '+str(binary)+': main -> alternate -> main; real CPU inference; index unchanged',flush=True)
    except Exception as error:
        reports.append({'binary':str(binary),'passed':False,'error':str(error)[:2000]})
        raise
    finally:
        subprocess.run([str(binary),'--runtime-internal','--stop'],env=env,capture_output=True,timeout=50)
        if old_runtime is not None and old_runtime.poll() is None:
            old_runtime.terminate(); old_runtime.wait(timeout=15)
        (BASE/'real-account-return-verification.json').write_text(json.dumps(reports,indent=2),encoding='utf-8')
(BASE/'real-account-return-verification.json').write_text(json.dumps(reports,indent=2),encoding='utf-8')
