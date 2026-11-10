#Signed software release verification tool (CIT4020)

# argparse allows us to use this single program to call multiple commands instead of needing to have multiple programs
import argparse 
import getpass #allows us to ask for a passphrase without storing it
import json #allows us to write the registry file
import os # This sets the file permissions
from pathlib import Path #this allows the program to handle the file path properly
from datetime import datetime, timezone
import hashlib

# Imports for helping us with key generation
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

class PayloadError(Exception):
    pass

# For verification
class ReleaseRejected(Exception):
    def __init__(self, reason): 
        self.reason = reason #assigning the reason of the rejection

# Work out the SHA-256 fingerprint of one file
def sha256_file(path):
    with open(path, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()


# Find every file in the payload folder and fingerprint each one
def collect_payload(payload_dir):
    payload_dir = Path(payload_dir)

    #The folder must exist
    if not payload_dir.is_dir():
        raise PayloadError("MISSING_PAYLOAD")

    results = []
    for item in payload_dir.rglob("*"):
        # Reject symbolic links
        if item.is_symlink():
            raise PayloadError("UNSAFE_PAYLOAD")
        if item.is_file():
            name = item.relative_to(payload_dir).as_posix()
            results.append((name, sha256_file(item)))
        elif not item.is_dir():
            # not a link, file or folder, so it is an unusual type
            raise PayloadError("UNSAFE_PAYLOAD")

    # An empty folder is also a failure
    if len(results) == 0:
        raise PayloadError("MISSING_PAYLOAD")

    results.sort()
    return results

# Method used to do the initial setup of the tool - (it will be ran once)
def run_setup(args):
    
    # Handles an empty publisher id and / or \\ characters
    publisher_id = args.publisher_id.strip() #removes all whitespaces from the publisher's id
    if publisher_id == "" or "/" in publisher_id or "\\" in publisher_id:
        print("Failed: due to a / or \\ within the id or it was empty. This is not allowed.")
        return 1

    # Organize where files will go
    workspace = Path(args.workspace)
    secrets_dir = workspace / "secrets"
    verifier_dir = workspace / "verifier"
    private_path = secrets_dir / "publisher_private.pem"
    public_name = publisher_id + "_public.pem"
    public_path = verifier_dir / public_name
    registry_path = verifier_dir / "trusted_publishers.json" 

    # Prevent overwriting files that exist already 
    for path in (private_path, public_path, registry_path):
        if path.exists():
            print("SETUP REFUSED: " + str(path) + " already exists. Nothing was changed.")
            return 1

    # request a pasphase from the user twice for verification
    passphrase = getpass.getpass("Choose a passphrase for the private key: ")
    again = getpass.getpass("Type the passphrase again: ")
    if passphrase == "":
        print("Setup Failed: the passphrase must not be empty.")
        return 1
    if passphrase != again:
        print("Setup Failed: the two passphrases did not match.")
        return 1

    #  we generate the key pair and then turn both halves into Privacy Enhanced Mail (PEM) bytes.
    private_key = Ed25519PrivateKey.generate() #generate the private key
    private_pem = private_key.private_bytes( #export as text
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption( #locks the text with the passphrase
            passphrase.encode("utf-8") # converts the passphrase into bytes
        ),
    )
    public_pem = private_key.public_key().public_bytes( #exports the pulic half into bytes which is not encrypted
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    passphrase = None  # drop our passphase as soon as we are done with it
    again = None 

    # create the folders and write the key files without overwriting.
    secrets_dir.mkdir(parents=True, exist_ok=True)
    verifier_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(secrets_dir, 0o700)
    try:
        with open(private_path, "xb") as f:   # "x" = fail if the file exists
            f.write(private_pem)
        os.chmod(private_path, 0o600) # only the owner can access the folder and has read write access
        with open(public_path, "xb") as f: 
            f.write(public_pem)

        # Write the trust registry.
        registry = {
            "publishers": [
                {
                    "publisher_id": publisher_id,
                    "public_key_path": "verifier/" + public_name,
                    "enabled": True, 
                }
            ]
        }
        with open(registry_path, "x", encoding="utf-8") as f:
            json.dump(registry, f, indent=2)
            f.write("\n") #writes as JSON file
    except FileExistsError as error:
        print("Error, the set up was refused. A file appeared while writing: " + str(error))
        return 1

    # Success message that prints locations only and never the actual key contents.
    print("SETUP OK for publisher '" + publisher_id + "'")
    print("  Encrypted private key: " + str(private_path))
    print("  Public key:            " + str(public_path))
    print("  Trust registry:        " + str(registry_path))
    return 0

def append_log(record):
    with open("release_log.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")

def log_sign(args, result, reason):
    append_log({
        "utc_time": datetime.now(timezone.utc).isoformat(),
        "operation": "sign",
        "release_folder": str(args.release),
        "publisher_id": args.publisher_id,
        "result": result,
        "reason": reason,
    })


def sign_fail(args, reason):
    print("SIGN FAILED: " + reason) # dsiplay the reason why the sign failed
    log_sign(args, "FAILED", reason) #log the failure that has occured
    return 1

# Method used to run the signing mechanism 
def run_sign(args):
    workspace = Path(args.workspace)
    release_dir = Path(args.release)

    # find and fingerprint each payload file
    try:
        files = collect_payload(release_dir / "payload")
    except PayloadError as e:
        return sign_fail(args, str(e))

    # check if the publisher is in the trust registry
    registry_path = workspace / "verifier" / "trusted_publishers.json"
    try:
        with open(registry_path, "r", encoding="utf-8") as f:
            registry = json.load(f)
    except (OSError, ValueError):
        return sign_fail(args, "TRUST_STORE_ERROR")
    found = False
    public_key_path = None
    for entry in registry.get("publishers", []):
        if entry.get("publisher_id") == args.publisher_id:
            found = True
            public_key_path = entry.get("public_key_path")
    if not found:
        return sign_fail(args, "UNKNOWN_PUBLISHER")

    # read the encrypted private key file
    private_path = workspace / "secrets" / "publisher_private.pem"
    try:
        with open(private_path, "rb") as f:
            private_pem = f.read()
    except OSError:
        return sign_fail(args, "MISSING_PRIVATE_KEY")

    # ask for the passphrase (from setup) and unlock the key
    passphrase = getpass.getpass("Passphrase for the private key: ")
    try:
        private_key = serialization.load_pem_private_key(
            private_pem, password=passphrase.encode("utf-8"))
    except ValueError:
        return sign_fail(args, "WRONG_PASSPHRASE")
    passphrase = None
        # the unlocked key must match the registered public key
    try:
        with open(workspace / public_key_path, "rb") as f:
            registered_key = serialization.load_pem_public_key(f.read())
    except (OSError, ValueError, TypeError):
        return sign_fail(args, "TRUST_STORE_ERROR")
    raw = serialization.Encoding.Raw
    raw_format = serialization.PublicFormat.Raw
    unlocked_public = private_key.public_key().public_bytes(raw, raw_format)
    if unlocked_public != registered_key.public_bytes(raw, raw_format):
        return sign_fail(args, "KEY_MISMATCH")

    # Build the manifest as a python dictionary
    file_list = []
    for name, digest in files:
        file_list.append({"path": name, "sha256": digest})
    manifest = {
        "publisher_id": args.publisher_id,
        "release_name": release_dir.resolve().name,
        "files": file_list,
    }

    # turn it into bytes ONCE, then sign those exact bytes
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    signature = private_key.sign(manifest_bytes)

    # we now write output files (temp file first and then we swap in)
    manifest_path = release_dir / "manifest.json"
    signature_path = release_dir / "signature.sig"
    with open(str(manifest_path) + ".tmp", "wb") as f:
        f.write(manifest_bytes)
    with open(str(signature_path) + ".tmp", "wb") as f:
        f.write(signature)
    os.replace(str(manifest_path) + ".tmp", manifest_path)
    os.replace(str(signature_path) + ".tmp", signature_path)

    # report success and then log it
    print("SIGNED " + release_dir.resolve().name)
    log_sign(args, "SIGNED", "OK")
    return 0

def now_utc():
    return datetime.now(timezone.utc).isoformat()

# A manifest path is safe only if it is a plain relative path with no tricks
def safe_manifest_path(raw):
    if not isinstance(raw, str) or raw == "":
        return False
    if raw.startswith("/"):        # absolute path
        return False
    if ".." in raw:                # tries to climb out of payload/
        return False
    if "\\" in raw or ":" in raw:  # backslashes and drive letters like C:
        return False
    for part in raw.split("/"):    # no empty or "." pieces, e.g. "a//b" or "./a"
        if part == "" or part == ".":
            return False
    return True

# Runs the five checks IN ORDER. The first failure raises ReleaseRejected.
def check_all_stages(args, record):
    release_dir = Path(args.release)
    workspace = Path(args.workspace)

    # ---------- Stage 1: manifest and signature files exist and are well formed ----------
    manifest_path = release_dir / "manifest.json"
    signature_path = release_dir / "signature.sig"

    if not manifest_path.is_file() or not signature_path.is_file():
        raise ReleaseRejected("INVALID_MANIFEST")

    try:
        # read as BYTES and keep them exactly as they are (stage 3 needs these)
        with open(manifest_path, "rb") as f:
            manifest_bytes = f.read()
        with open(signature_path, "rb") as f:
            signature_bytes = f.read()
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (OSError, ValueError):
        raise ReleaseRejected("INVALID_MANIFEST")

    if not isinstance(manifest, dict):
        raise ReleaseRejected("INVALID_MANIFEST")

    publisher_id = manifest.get("publisher_id")
    release_name = manifest.get("release_name")
    files = manifest.get("files")

    if not isinstance(publisher_id, str) or publisher_id == "":
        raise ReleaseRejected("INVALID_MANIFEST")
    if not isinstance(release_name, str) or release_name == "":
        raise ReleaseRejected("INVALID_MANIFEST")
    if not isinstance(files, list):
        raise ReleaseRejected("INVALID_MANIFEST")

    seen_paths = set()
    for item in files:
        if not isinstance(item, dict):
            raise ReleaseRejected("INVALID_MANIFEST")
        path = item.get("path")
        digest = item.get("sha256")
        if not isinstance(path, str) or not isinstance(digest, str):
            raise ReleaseRejected("INVALID_MANIFEST")
        # a sha256 hash is exactly 64 lowercase hex characters
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ReleaseRejected("INVALID_MANIFEST")
        if path in seen_paths:     # the same file listed twice
            raise ReleaseRejected("INVALID_MANIFEST")
        seen_paths.add(path)

    record["publisher_id"] = publisher_id   # now the log can name the publisher

    # ---------- Stage 2: is the publisher trusted and enabled? ----------
    registry_path = workspace / "verifier" / "trusted_publishers.json"
    try:
        with open(registry_path, "r", encoding="utf-8") as f:
            registry = json.load(f)
        publishers = registry["publishers"]
        if not isinstance(publishers, list):
            raise ValueError("publishers must be a list")
    except (OSError, ValueError, KeyError, TypeError):
        raise ReleaseRejected("TRUST_STORE_ERROR")

    entry = None
    for candidate in publishers:
        if isinstance(candidate, dict) and candidate.get("publisher_id") == publisher_id:
            entry = candidate
    if entry is None:
        raise ReleaseRejected("UNKNOWN_PUBLISHER")
    if entry.get("enabled") is not True:     # disabled BEFORE any signature check
        raise ReleaseRejected("PUBLISHER_DISABLED")

    # ---------- Stage 3: is the signature valid? ----------
    # The public key comes from OUR registry, never from the release folder.
    key_path = entry.get("public_key_path")
    if not isinstance(key_path, str):
        raise ReleaseRejected("TRUST_STORE_ERROR")
    try:
        with open(workspace / key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except (OSError, ValueError):
        raise ReleaseRejected("TRUST_STORE_ERROR")
    if not isinstance(public_key, Ed25519PublicKey):
        raise ReleaseRejected("TRUST_STORE_ERROR")

    try:
        # check the signature against the ORIGINAL manifest bytes from stage 1
        public_key.verify(signature_bytes, manifest_bytes)
    except InvalidSignature:
        raise ReleaseRejected("BAD_SIGNATURE")

    # ---------- Stage 4: are all manifest paths safe? ----------
    # (We never open a manifest path directly; this is still checked first.)
    for item in files:
        if not safe_manifest_path(item["path"]):
            raise ReleaseRejected("UNSAFE_PATH")

    # ---------- Stage 5: do the real files match the manifest exactly? ----------
    try:
        actual = dict(collect_payload(release_dir / "payload"))   # {path: hash}
    except PayloadError as e:
        if str(e) == "UNSAFE_PAYLOAD":      # symbolic link or odd file type
            raise ReleaseRejected("UNSAFE_PATH")
        raise ReleaseRejected("MISSING_FILE")   # payload folder missing or empty

    listed = {}
    for item in files:
        listed[item["path"]] = item["sha256"]

    for path in sorted(listed):             # a listed file is absent
        if path not in actual:
            raise ReleaseRejected("MISSING_FILE")
    for path in sorted(actual):             # a real file is not listed
        if path not in listed:
            raise ReleaseRejected("EXTRA_FILE")
    for path in sorted(listed):             # a file's contents changed
        if actual[path] != listed[path]:
            raise ReleaseRejected("HASH_MISMATCH")

# Method used to run the verification of signed packages
def run_verify(args):
    record = {"utc_time": now_utc(), "operation": "verify",
                "release_folder": str(args.release), "publisher_id": None}
    try:
        check_all_stages(args, record)
        record.update(result="ACCEPTED", reason="OK")
        code = 0
    except ReleaseRejected as e:
        record.update(result="REJECTED", reason = e.reason)
        code = 1
    except Exception:
        # Safety net: any unexpected crash is a rejection, never an acceptance
        record.update(result="REJECTED", reason="INTERNAL_ERROR")
        code = 1
    append_log(record)
    print("ACCEPTED" if code == 0 else "REJECTED " + record["reason"])
    return code


def main():
    parser = argparse.ArgumentParser (description = "signed Software Release Verification")
    sub = parser.add_subparsers(dest="command", required = True)
    p_setup = sub.add_parser("setup") #creating the setup command to be used
    #Each Flag is accepted by the command
    p_setup.add_argument("--publisher-id", required = True)
    p_setup.add_argument("--workspace", default=".")

    p_sign = sub.add_parser("sign") #creating the sign command to be used
    p_sign.add_argument("--publisher-id", required = True)
    p_sign.add_argument("--release", required = True)
    p_sign.add_argument("--workspace", default=".")

    p_verify = sub.add_parser("verify") #creating the verify command to be used
    p_verify.add_argument("--release", required = True)
    p_verify.add_argument("--workspace", default=".")


    args=parser.parse_args()

    if args.command == "setup":
        return run_setup(args)

    if args.command == "sign":
        return run_sign(args)
    
    if args.command == "verify":
        return run_verify(args)

if __name__ == '__main__': 
    raise SystemExit(main())
