#Signed software release verification tool (CIT4020)

#argparse allows us to use this single program to call multiple commands instead of needing to have multiple programs
import argparse 

#Method used to do the initial setup of the tool - (it will be ran once)
def run_setup(args):
    print("Setup is not yet configured")
    return 0

#Method used to run the signing mechanism 
def run_sign(args):
    print("Sign is not yet configured")
    return 0

#Method used to run the verification of signed packages
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
    
    if args.command == "verify":
        return run_verify(args)

if __name__ == '__main__': raise SystemExit(main())