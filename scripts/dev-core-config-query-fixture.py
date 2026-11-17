"""Real Runtime24 reply-loss proxy for the Windows WebView query diagnostic.

Adapted from the directed native-core-unknown-review proof. Control requests are
fixture-only; every product request/response is forwarded to the real Runtime.
"""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import re
import stat
import subprocess
import threading
import urllib.request
import zipfile

TARGETS = {
    'windows-amd64': ['respire-windows-amd64.exe', 'respire-windows-amd64-setup.exe'],
    'windows-arm64': ['respire-windows-arm64.exe', 'respire-windows-arm64-setup.exe'],
    'darwin-amd64': ['respire-darwin-amd64.zip'],
    'darwin-arm64': ['respire-darwin-arm64.zip', 'respire-darwin-arm64.dmg'],
    'linux-amd64': ['respire-linux-amd64.tar.gz'],
    'linux-arm64': ['respire-linux-arm64.tar.gz'],
}


def sealed_candidate(args):
    """Read-only consumer of James's package_checks schema; never a GUI pass."""
    def api(path):
        return json.loads(subprocess.check_output(['gh', 'api', path]))
    require(args.run_id > 0 and args.attempt > 0 and args.artifact_id > 0
            and re.fullmatch(r'[0-9a-f]{40}', args.source), 'Exact Client2 source and positive IDs required')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', args.artifact_digest), 'Exact ZIP digest required')
    repo = 'risense-ai/respire-client2'
    run = api(f'repos/{repo}/actions/runs/{args.run_id}')
    workflow = api(f'repos/{repo}/actions/workflows/desktop.yml')
    require(run['repository']['full_name'] == run['head_repository']['full_name'] == repo
            and run['workflow_id'] == workflow['id'] and run['path'] == '.github/workflows/desktop.yml'
            and run['event'] == 'workflow_dispatch' and run['head_branch'] == 'main'
            and run['head_sha'] == args.source and run['run_attempt'] == args.attempt
            and run['status'] == 'completed' and run['conclusion'] == 'success', 'Sealed producer differs')
    pages = json.loads(subprocess.check_output(['gh', 'api', '--paginate', '--slurp',
                        f'repos/{repo}/actions/runs/{args.run_id}/artifacts?per_page=100']))
    matches = [a for page in pages for a in page['artifacts']
               if a['name'] == f'desktop-package-checks-{args.attempt}']
    require(len(matches) == 1, 'Sealed artifact is missing or ambiguous')
    artifact = matches[0]
    require(artifact['id'] == args.artifact_id and artifact['digest'] == args.artifact_digest
            and not artifact['expired'] and artifact['workflow_run']['id'] == args.run_id
            and artifact['workflow_run']['head_sha'] == args.source, 'External artifact identity differs')
    require(not args.output.exists(), 'Sealed output must be new')
    archive = args.output.with_suffix('.zip')
    require(not archive.exists(), 'Sealed ZIP path must be new')
    with archive.open('xb') as output:
        subprocess.run(['gh', 'api', f'repos/{repo}/actions/artifacts/{args.artifact_id}/zip'], stdout=output, check=True)
    require(archive.stat().st_size == artifact['size_in_bytes']
            and 'sha256:' + digest(archive) == args.artifact_digest, 'Downloaded sealed ZIP differs')
    assets = {name for names in TARGETS.values() for name in names}
    files = assets | {'SHA256SUMS', 'LICENSE.txt', 'THIRD_PARTY_NOTICES.txt', 'release-notes.md'}
    archive_files = files | {'client-updates.json', 'candidate.json', 'package-checks.json'}
    with zipfile.ZipFile(archive) as zipped:
        entries = zipped.infolist()
        require(len(entries) == len(archive_files) and {e.filename for e in entries} == archive_files
                and all(not stat.S_ISLNK(e.external_attr >> 16) for e in entries), 'Unsafe sealed ZIP inventory')
        zipped.extractall(args.output)
    manifest = json.loads((args.output / 'candidate.json').read_text(encoding='utf-8'))
    producer = {'repository': repo, 'run_id': str(args.run_id), 'attempt': args.attempt}
    require(set(manifest) == {'schema_version', 'scope', 'source', 'version', 'producer', 'targets', 'files', 'discovery_index'}
            and type(manifest['schema_version']) is int and manifest['schema_version'] == 1 and manifest['scope'] == 'package_checks'
            and manifest['source'] == args.source and manifest['version'] == '2.0.0-dev.17'
            and manifest['producer'] == producer and type(manifest['producer']['attempt']) is int
            and manifest['targets'] == TARGETS
            and set(manifest['files']) == files, 'Sealed version/source/six-target schema differs')
    for name, info in manifest['files'].items():
        path = args.output / name
        require(type(info['size']) is int and info['size'] > 0
                and info == {'sha256': digest(path), 'size': path.stat().st_size}, 'Sealed payload differs')
    # This validates only the initial sealed index. It is not a permanent
    # immutability claim about the stable release's discovery URL.
    index = args.output / 'client-updates.json'
    require(manifest['discovery_index'] == {'filename': 'client-updates.json', 'role': 'version_update_manifest',
            'initial': {'sha256': digest(index), 'size': index.stat().st_size}, 'stable_record_sha256': None}
            and type(manifest['discovery_index']['initial']['size']) is int and index.stat().st_size > 0,
            'Initial DEV discovery index binding differs')
    candidate_hash = digest(args.output / 'candidate.json')
    receipts = json.loads((args.output / 'package-checks.json').read_text(encoding='utf-8'))
    require(len(receipts) == 6 and {r['target'] for r in receipts} == set(TARGETS), 'Six package receipts required')
    for receipt in receipts:
        require(receipt == {'scope': 'package_checks', 'target': receipt['target'], 'status': 'passed',
                            'candidate_sha256': candidate_hash, 'producer': producer}
                and type(receipt['producer']['attempt']) is int, 'Sealed receipt differs')
    sums = (args.output / 'SHA256SUMS').read_text().splitlines()
    require(len(sums) == 9 and set(sums) == {f"{manifest['files'][name]['sha256']}  {name}" for name in assets}, 'Sealed checksum set differs')
    proof = {'artifact_id': args.artifact_id, 'zip_digest': args.artifact_digest, 'source': args.source,
             'version': manifest['version'], 'producer': producer, 'manifest_sha256': candidate_hash,
             'exe_sha256': manifest['files']['respire-windows-amd64.exe']['sha256'],
             'discovery_index': manifest['discovery_index'],
             'package_checks': 'passed', 'gui_acceptance': 'not-evaluated'}
    args.output.with_suffix('.json').write_text(json.dumps(proof, indent=2), encoding='utf-8')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_owner(port, image, profile, expected_hash):
    request = urllib.request.Request(f"http://127.0.0.1:{port}/api/health",
                                    headers={"X-Respire-Health": "runtime-v1"})
    with urllib.request.urlopen(request, timeout=10) as response:
        owner = json.load(response)
    require(owner["runtime_version"] == "2.0.0-dev.24" and owner["startup_complete"] is True,
            "Real Runtime24 startup not complete")
    require(Path(owner["exe"]).resolve() == image.resolve()
            and Path(owner["data_dir"]).resolve() == profile.resolve()
            and Path(owner["installation_root"]).resolve() == profile.resolve()
            and owner["image_sha256"] == digest(image) == expected_hash,
            "Runtime health/image/profile differs")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                               wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    handle = kernel.OpenProcess(0x1000, False, owner["pid"])
    require(bool(handle), "Cannot inspect Runtime owner")
    try:
        size, name = wintypes.DWORD(32768), ctypes.create_unicode_buffer(32768)
        require(kernel.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(size)),
                "Cannot inspect Runtime image")
        require(Path(name.value).resolve() == image.resolve(), "Runtime OS image differs")
        times = [wintypes.FILETIME() for _ in range(4)]
        require(kernel.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)),
                "Cannot inspect Runtime birth")
        birth = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        require(owner["process_start_id"] == f"windows-filetime-{birth}", "Runtime birth differs")
    finally:
        kernel.CloseHandle(handle)
    return owner


def serve(args):
    require(os.name == "nt" and "RSRS_CORE_TEST_MODE" not in os.environ,
            "Require Windows with CORE_TEST_MODE absent")
    owner = runtime_owner(args.port, args.image, args.profile, args.image_sha256)
    scope = {key: owner[key] for key in ("account_id", "instance_id", "generation")}
    lock = threading.Lock()
    state = {"mode": "idle", "operation_id": None, "apply_ids": [], "result_ids": [],
             "dropped_apply_replies": 0, "result_issued": 0, "result_forwarded": 0,
             "result_response_lost": 0, "errors": [], "core_test_mode": False, "scope": scope,
             "apply_fusion": None, "effective_fusion": None}
    nonce = secrets.token_hex(32)

    def verify_owner():
        live = runtime_owner(args.port, args.image, args.profile, args.image_sha256)
        for key in ('pid', 'process_start_id', 'image_sha256', 'installation_id', 'account_id', 'instance_id', 'generation'):
            require(live[key] == owner[key], 'Real Runtime owner changed')

    def snapshot():
        return {key: json.loads(json.dumps(state[key])) for key in (
            'operation_id', 'apply_ids', 'result_ids', 'result_issued', 'result_forwarded',
            'result_response_lost', 'dropped_apply_replies', 'errors', 'core_test_mode', 'scope',
            'apply_fusion', 'effective_fusion')}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def close_reply(self):
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()

        def do_GET(self):
            self.handle_request()

        def do_POST(self):
            self.handle_request()

        def handle_request(self):
            try:
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.path == "/__fixture":
                    require(self.headers.get("X-Fixture-Control") == nonce, "Wrong fixture control identity")
                    verify_owner()
                    with lock:
                        if self.command == "POST":
                            mode = json.loads(body)["mode"]
                            require(mode in ("lose_reply", "drop_results", "pass"), "Unknown control mode")
                            if mode == "lose_reply":
                                require(not state["apply_ids"] and state["mode"] == "idle", "Cannot rearm apply")
                            else:
                                require(len(state["apply_ids"]) == 1, "No single original apply")
                            state["mode"] = mode
                        payload = json.dumps(snapshot()).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                require(self.path in ("/api/health", "/api/rpc", "/api/runtime/stop"),
                        "Unexpected Runtime path")
                rpc = json.loads(body) if self.path == "/api/rpc" and body else {}
                method = rpc.get("method")
                apply = method == "core_config.apply"
                result = method == "runtime.result"
                drop_result_reply = False
                if apply or result:
                    verify_owner()
                with lock:
                    if apply:
                        require(not state["apply_ids"] and state["mode"] == "lose_reply", "Unexpected/replayed apply")
                        require(rpc["scope"] == scope, "Apply scope differs from Runtime owner")
                        candidate = json.loads(rpc["args"][0])["candidate"]
                        require(candidate["recall_fusion"]["fusion"] == "attention",
                                "Real GUI did not select attention fusion")
                        state["apply_fusion"] = candidate["recall_fusion"]["fusion"]
                        state["operation_id"] = rpc["operation_id"]
                        state["apply_ids"].append(rpc["operation_id"])
                    if result:
                        require(rpc["operation_id"] == state["operation_id"] and rpc["scope"] == scope,
                                "Result is not the original operation/scope")
                        state["result_ids"].append(rpc["operation_id"])
                        state["result_issued"] += 1
                        drop_result_reply = state["mode"] == "drop_results"
                connection = http.client.HTTPConnection("127.0.0.1", args.port, timeout=30)
                try:
                    headers = {k: v for k, v in self.headers.items()
                               if k.lower() not in ("host", "connection", "content-length")}
                    connection.request(self.command, self.path, body=body, headers=headers)
                    if result:
                        with lock:
                            state["result_forwarded"] += 1
                    response = connection.getresponse()
                    data, status = response.read(), response.status
                    response_type = response.getheader("Content-Type", "application/json")
                finally:
                    connection.close()
                if result and drop_result_reply:
                    value = json.loads(data)
                    require(status == 200 and value['ok'] is True
                            and value['id'] == rpc['id'] and value['scope'] == scope,
                            'Real Runtime did not return the original result response')
                    with lock:
                        state['result_response_lost'] += 1
                    self.close_reply()
                    return
                if apply:
                    value = json.loads(data)
                    require(status == 200 and value["ok"] is True
                            and value["id"] == rpc["operation_id"] and value["scope"] == scope,
                            "Real Runtime did not successfully apply the original request")
                    summary = value["envelope"]["summary"]
                    require(summary["state"] == "applied" and summary["candidate"] == candidate
                            and summary["effective"]["recall_fusion"]["fusion"] == "attention",
                            "Real Runtime did not apply the selected attention fusion")
                    with lock:
                        state["effective_fusion"] = summary["effective"]["recall_fusion"]["fusion"]
                        state["dropped_apply_replies"] += 1
                        state["mode"] = "drop_results"
                    self.close_reply()
                    return
                self.send_response(status)
                self.send_header("Content-Type", response_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as error:
                # Never log payloads, headers, private material or dynamic parameters.
                with lock:
                    state["errors"].append(type(error).__name__)
                self.close_connection = True

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    address = f"http://127.0.0.1:{server.server_port}"
    args.ready.write_text(json.dumps({"address": address, "nonce": nonce,
                                      "runtime_owner": owner}), encoding="utf-8")
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    proxy = commands.add_parser('serve')
    proxy.add_argument("--port", type=int, required=True)
    proxy.add_argument("--image", type=Path, required=True)
    proxy.add_argument("--image-sha256", required=True)
    proxy.add_argument("--profile", type=Path, required=True)
    proxy.add_argument("--ready", type=Path, required=True)
    sealed = commands.add_parser('sealed')
    sealed.add_argument('--run-id', type=int, required=True)
    sealed.add_argument('--attempt', type=int, required=True)
    sealed.add_argument('--source', required=True)
    sealed.add_argument('--artifact-id', type=int, required=True)
    sealed.add_argument('--artifact-digest', required=True)
    sealed.add_argument('--output', type=Path, required=True)
    parsed = parser.parse_args()
    if parsed.action == 'sealed':
        sealed_candidate(parsed)
    else:
        serve(parsed)
