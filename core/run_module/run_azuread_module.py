#import azure.identity
import core.auth.auth_azuread
'''
+ get_authority_url
+ DeviceCode
   - ClientID
+ InteractiveBrowser
   - No Args
+ User & Pass
+ Service Principal user + pass
+ Service Principal Certifiate
'''

def run_azuread_module(imported_module, all_sessions, cred_prof, workspace, useragent=""):
    global tokendata
    if imported_module.needs_creds:
        print("You ran an azure module")
    else:
        return imported_module.exploit(workspace)
