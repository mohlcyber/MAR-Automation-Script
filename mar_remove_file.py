#Written by mohlcyber
#v.0.3 MAR Python API
#based on a hash script will automatically launch query and tries to delete files (RemoveFile)

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

		self.query = args.hash

	def create_search(self):
		queryId = None

		if len(str(self.query)) == 32:
			type = 'md5'
		elif len(str(self.query)) == 40:
			type = 'sha1'
		elif len(str(self.query)) == 64:
			type = 'sha256'
		else:
			print('Something went wrong with the Hash input')
			sys.exit()

		payload = {
			"projections": [
				{
					"name": "HostInfo",
					"outputs": ["hostname", "ip_address"]
				}, {
					"name": "Files",
					"outputs": ["name", str(type), "status", "full_name"]
				}
			],
			"condition": {
				"or": [{
					"and": [{
						"name": "Files",
						"output": str(type),
						"op": "EQUALS",
						"value": str(self.query)
					}]
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

		if res.status_code == 200:
			try:
				items = res.json()['totalItems']

				react_summary = []
				for item in res.json()['items']:
					if item['output']['Files|status'] != 'deleted':
						react_dict = {}
						react_dict[item['id']] = item['output']['Files|full_name']
						react_summary.append(react_dict)

				print('RESULT: MAR found {} System/s with this hash. {} of them with the file status CURRENT.'.format(items, len(react_summary)))

				return react_summary

			except Exception as e:
				print('ERROR: Something went wrong to retrieve the results. Error: {}'.format(e))
		else:
			print('ERROR: Something went wrong to retrieve the results.')

	def reactions(self):
		react_id = None
		arg_name = None
		res = requests.get(self.url + '/rest/mar/v1/reactions?$offset=0&$limit=1000',
						   headers=self.headers,
						   auth=self.auth,
						   verify=self.verify)

		if res.status_code == 200:
			try:
				for item in res.json()['items']:
					if item['name'] == 'RemoveFile':
						react_id = item['id']
					for arg in item['arguments']:
						arg_name = arg['name']

			except Exception as e:
				print('ERROR: Something went wrong to retrieve MAR reaction ID. Error: {}'.format(e))
				sys.exit()

		return react_id, arg_name

	def create_reaction(self, react_id, queryId, system_id, file_path, arg_name):
		reaction_id = None
		payload = {
			"reactionId": str(react_id),
			"queryId": str(queryId),
			"resultIds": [str(system_id)],
			"reactionArguments": {arg_name: {"value": str(file_path)}}
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
	usage = """Usage: mar_api.py -i <ip> -p <port> -U <username> -P <password> -H <hash>"""
	title = 'McAfee MAR Python API'
	parser = argparse.ArgumentParser(description=title)
	parser.add_argument('--epoip', '-i', required=True, type=str)
	parser.add_argument('--epoport', '-p', required=True, default='8443', type=int)
	parser.add_argument('--epousername', '-U', required=True, type=str)
	parser.add_argument('--epopassword', '-P', required=True, type=str)
	parser.add_argument('--hash', '-H', required=True, type=str)

	args = parser.parse_args()

	mar = MAR()

	#Create, Start, Get Status and Result for Hashes search
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

	if results == []:
		print('INFO: All Files deleted on Systems')
		sys.exit()

	# react_id, arg_name = mar.reactions()
	# if react_id is None or arg_name is None:
	# 	print('ERROR: Could not find the appropriated MAR reaction')

	#Create and Execute Reaction
	for result in results:
		for system_id, file_path in result.items():
			#reaction_id = mar.create_reaction(react_id, queryId, system_id, file_path, arg_name)
			reaction_id = mar.create_reaction('7', queryId, system_id, file_path, 'full_name')

			if reaction_id is None:
				print('ERROR: Could not create new MAR reaction')
				sys.exit()

			if mar.start_reaction(reaction_id) is False:
				print('ERROR: Something went wrong starting MAR reaction')
				sys.exit()

			while mar.status_reaction(reaction_id) is False:
				print('STATUS: Waiting for 5 seconds to check again.')
				time.sleep(5)
