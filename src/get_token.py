from cloudshell.api.cloudshell_api import CloudShellAPISession

ses = CloudShellAPISession('192.168.0.112', 'admin', 'admin')
print(ses.authentication.xmlrpc_token)