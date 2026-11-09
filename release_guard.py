#Signed software release verification tool (CIT4020)

# argparse allows us to use this single program to call multiple commands instead of needing to have multiple programs
import argparse 

import getpass #allows us to ask for a passphrase without storing it
import json #allows us to write the registry file
import os # This sets the file permissions
from pathlib import Path #this allows the program to handle the file path properly

# Imports for helping us with key generation
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
        print("SETUP FAILED: the passphrase must not be empty.")
        return 1
    if passphrase != again:
        print("SETUP FAILED: the two passphrases did not match.")
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

# Method used to run the signing mechanism 
def run_sign(args):
    print("Sign is not yet configured")
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

    if args.command("sign"):
        return run_sign(args)
    
    if args.command == "verify":
        return run_verify(args)

if __name__ == '__main__': 
    raise SystemExit(main())


main()