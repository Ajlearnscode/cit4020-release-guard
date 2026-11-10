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

class PayloadError(Exception):
    pass


# 4.3.1 Work out the SHA-256 fingerprint of one file
def sha256_file(path):
    with open(path, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()


# 4.3.2 Find every file in the payload folder and fingerprint each one
def collect_payload(payload_dir):
    payload_dir = Path(payload_dir)

    # 4.3.4 The folder must exist
    if not payload_dir.is_dir():
        raise PayloadError("MISSING_PAYLOAD")

    results = []
    for item in payload_dir.rglob("*"):
        # 4.3.3 Reject symbolic links
        if item.is_symlink():
            raise PayloadError("UNSAFE_PAYLOAD")
        if item.is_file():
            name = item.relative_to(payload_dir).as_posix()
            results.append((name, sha256_file(item)))
        elif not item.is_dir():
            # not a link, file or folder, so it is an unusual type
            raise PayloadError("UNSAFE_PAYLOAD")

    # 4.3.4 An empty folder is also a failure
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
    print("SETUP OK for publisher'" + publisher_id + "'")
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
    print("Sign Failed: " + reason) # dsiplay the reason why the sign failed
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

# Method used to run the verification of signed packages
def run_verify(args):
    print("Verify is not yet coinfigured")
    return 0


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
