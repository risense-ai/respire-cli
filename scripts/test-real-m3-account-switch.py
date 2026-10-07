"""Read-only real M3 cache; disposable profiles and owned runtime port only."""
import argparse, hashlib, hmac, json, os, pathlib, secrets, socket, sqlite3, subprocess, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

parser=argparse.ArgumentParser()
parser.add_argument('--binary',action='append',required=True)
parser.add_argument('--model-dir',required=True)
parser.add_argument('--output-dir',required=True)
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
    try:
        run('--direct','model','engine','cpu')
        global_engine=(main/'inference.json').read_bytes()
        for profile in [main,alternate]:
            (main/'client.json').write_text(json.dumps({'data_dir':str(profile)}),encoding='utf-8')
            run('--direct','remember','Real account return fixture '+profile.name,'--title',profile.name,'--force')
        original = {str(profile):snapshot(profile) for profile in [main,alternate]}
        (main/'client.json').write_text(json.dumps({'data_dir':str(main)}),encoding='utf-8')
        statuses=[]
        for account, profile in [('main',main),('alternate',alternate),('main',main)]:
            run('account','use',account)
            assert run('model','engine')['summary']['engine']=='cpu'
            assert (main/'inference.json').read_bytes()==global_engine
            assert not (alternate/'inference.json').exists()
            run('model','probe','--model','m3')
            doctor=run('doctor',allow_failure=True)
            rows={item['name']:item for item in doctor['items'] if item['name'] in ['embedder','model index']}
            assert len(rows)==2 and all(item['status']=='ok' for item in rows.values()),rows
            assert pathlib.Path(json.loads((main/'client.json').read_text())['data_dir'])==profile
            assert snapshot(profile)==original[str(profile)],'switch/probe changed source data or rebuilt existing index'
            statuses.append({'account':account,'model_rows':rows})
        reports.append({'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'binary':str(binary),'passed':True,
            'real_model':True,'engine':'cpu','global_engine_preserved':True,'distinct_vault_keys':True,'sequence':statuses,'index_source_and_keys_unchanged':True,'fixture':str(root)})
        print('PASS '+str(binary)+': main -> alternate -> main; real CPU inference; index unchanged',flush=True)
    except Exception as error:
        reports.append({'binary':str(binary),'passed':False,'error':str(error)[:2000]})
        raise
    finally:
        subprocess.run([str(binary),'--runtime-internal','--stop'],env=env,capture_output=True,timeout=50)
        (BASE/'real-account-return-verification.json').write_text(json.dumps(reports,indent=2),encoding='utf-8')
(BASE/'real-account-return-verification.json').write_text(json.dumps(reports,indent=2),encoding='utf-8')
