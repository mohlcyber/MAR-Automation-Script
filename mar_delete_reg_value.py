# Written by mohlcyber
# v.0.1 MAR Python API
# based on a registry path and value the script will automatically launch query
# and tries to delete the registry key (Delete Registry Value)

import sys
import json
import time
import argparse
import requests

requests.packages.urllib3.disable_warnings()


class MAR():

	def __init__(self):
		base_url = args.epoip
		port = args.epoport
		self.url = 'https://{0}:{1}'.format(base_url, port)
		self.headers = {'Content-Type': 'application/json'}
		self.verify = False

		user = args.epousername
		pw = args.epopassword
		self.auth = (user, pw)

		self.regpath = args.regpath
		self.regvalue = args.regvalue

	def create_search(self):
		queryId = None

		payload = {
			"projections": [
				{
					"name": "HostInfo",
					"outputs": ["hostname", "ip_address"]
				}, {
					"name": "WinRegistry",
					"outputs": ["keypath", "keyvalue"]
				}
			],
			"condition": {
				"or": [{
					"and": [
						{
							"name": "WinRegistry",
							"output": "keypath",
							"op": "EQUALS",
							"value": str(self.regpath)
						},
						{
							"name": "WinRegistry",
							"output": "keyvalue",
							"op": "EQUALS",
							"value": str(self.regvalue)
						}
					]
				}]
			}
		}

		res = requests.post(self.url + '/rest/mar/v1/searches/simple',
							headers=self.headers,
							auth=self.auth,
							data=json.dumps(payload),
							verify=self.verify)

		if res.status_code == 200:
			try:
				queryId = res.json()['id']
				print('CREATION: MAR search got created successfully')
			except Exception as e:
				print('ERROR: Could not find the search ID. Error: {}'.format(e))
				sys.exit()

		return queryId

	def start_search(self, queryId):
		started = False

		res = requests.put(self.url + '/rest/mar/v1/searches/{}/start'.format(queryId),
						   headers=self.headers,
						   auth=self.auth,
						   verify=self.verify)

		if res.status_code == 200:
			started = True
			print('CREATION: MAR search got started successfully')

		return started

	def status_search(self, queryId):
		done = False

		res = requests.get(self.url + '/rest/mar/v1/searches/{}/status'.format(queryId),
						   headers=self.headers,
						   auth=self.auth,
						   verify=self.verify)

		if res.status_code == 200:
			try:
				print('STATUS: MAR Search status is {}.'.format(res.json()['status']))
				if res.json()['status'] == 'FINISHED':
					done = True
			except Exception as e:
				print('ERROR: Could not get the search ID. Error: {}'.format(e))
				sys.exit()

		return done

	def results(self, queryId):
		res = requests.get(self.url + '/rest/mar/v1/searches/{}/results?$offset=0&$limit=1000'.format(queryId),
						   headers=self.headers,
						   auth=self.auth,
						   verify=self.verify)

		print(res.json())

		if res.status_code == 200:
			try:
				items = res.json()['totalItems']
				react_summary = []
				for item in res.json()['items']:
					react_dict = {}
					react_dict['id'] = item['id']
					react_dict['keypath'] = item['output']['WinRegistry|keypath']
					react_dict['keyvalue'] = item['output']['WinRegistry|keyvalue']
					react_summary.append(react_dict)

				print('RESULT: MAR found {} System/s.'.format(items))
				return react_summary

			except Exception as e:
				print('ERROR: Something went wrong to retrieve the results. Error: {}'.format(e))

	def reactions(self, reaction_name):
		react_id = None
		arg_name = None
		res = requests.get(self.url + '/rest/mar/v1/reactions?$offset=0&$limit=1000',
						   headers=self.headers,
						   auth=self.auth,
						   verify=self.verify)

		if res.status_code == 200:
			try:
				for item in res.json()['items']:
					if item['name'] == reaction_name:
						react_id = item['id']
					for arg in item['arguments']:
						arg_name = arg['name']

			except Exception as e:
				print('ERROR: Something went wrong to retrieve MAR reaction ID. Error: {}'.format(e))
				sys.exit()

		return react_id, arg_name

	def create_reaction(self, react_id, queryId, system_id, keypath, keyvalue):
		reaction_id = None
		payload = {
			"reactionId": str(react_id),
			"queryId": str(queryId),
			"resultIds": [str(system_id)],
			"reactionArguments": {
				"keypath": {
					"value": str(keypath)
				},
				"keyvalue": {
					"value": str(keyvalue)
				}
			}
		}

		res = requests.post(self.url + '/rest/mar/v1/reactionexecution',
							headers=self.headers,
							auth=self.auth,
							data=json.dumps(payload),
							verify=self.verify)

		if res.status_code == 200:
			try:
				reaction_id = res.json()['id']
			except Exception as e:
				print('ERROR: Something went wrong to create reaction. Error: {}'.format(e))
				sys.exit()

		return reaction_id

	def start_reaction(self, reaction_id):
		started = False
		res = requests.put(self.url + '/rest/mar/v1/reactionexecution/{}/execute'.format(str(reaction_id)),
						   headers=self.headers,
						   auth=self.auth,
						   verify=self.verify)
		if res.status_code == 200:
			started = True
			print('REACTION: MAR reaction got executed successfully')

		return started

	def status_reaction(self, reaction_id):
		done = False

		res = requests.get(self.url + '/rest/mar/v1/reactionexecution/{}/status'.format(str(reaction_id)),
						   headers=self.headers,
						   auth=self.auth,
						   verify=self.verify)

		if res.status_code == 200:
			try:
				print('STATUS: MAR Reaction status is {}.'.format(res.json()['status']))
				if res.json()['status'] == 'FINISHED':
					done = True
			except Exception as e:
				print('ERROR: Could not get the search ID. Error: {}'.format(e))
				sys.exit()

		return done


if __name__ == '__main__':
	usage = """Usage: mar_api.py -i <ip> -p <port> -U <username> -PW <password> -P <regpath> -V <regvalue>"""
	title = 'McAfee MAR Python API'
	parser = argparse.ArgumentParser(description=title)
	parser.add_argument('--epoip', '-i', required=True, type=str)
	parser.add_argument('--epoport', '-p', required=True, default='8443', type=int)
	parser.add_argument('--epousername', '-U', required=True, type=str)
	parser.add_argument('--epopassword', '-PW', required=True, type=str)
	parser.add_argument('--regpath', '-P', required=True, type=str)
	parser.add_argument('--regvalue', '-V', required=True, type=str)

	args = parser.parse_args()

	mar = MAR()
	queryId = mar.create_search()
	if queryId is None:
		print('ERROR: Something went wrong to create the search')
		sys.exit()

	if mar.start_search(queryId) is False:
		print('ERROR: Something went wrong to start the search')
		sys.exit()

	while mar.status_search(queryId) is False:
		print('STATUS: Waiting for 5 seconds to check again.')
		time.sleep(5)

	results = mar.results(queryId)

	if results is None or results == []:
		print('INFO: Could not any find Systems.')
		sys.exit()

	for result in results:
		reaction_id = mar.create_reaction('10', queryId, result['id'], result['keypath'], result['keyvalue'])
		if reaction_id is None:
			print('ERROR: Could not create new MAR reaction')
			sys.exit()

		if mar.start_reaction(reaction_id) is False:
			print('ERROR: Something went wrong starting MAR reaction')
			sys.exit()

		while mar.status_reaction(reaction_id) is False:
			print('STATUS: Waiting for 5 seconds to check again.')
			time.sleep(5)
