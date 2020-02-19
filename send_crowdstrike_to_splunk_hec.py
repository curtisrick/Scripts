#!/usr/bin/python
import os
import re
import gzip
import shutil
from datetime import datetime
from splunk_http_event_collector import http_event_collector

today = datetime.now()
dateStr = today.strftime('%m-%d-%y')
timeStr = today.strftime('%H:%M:%S')

rootdir = '/opt/crowdstrike/data'
oldDir = '/opt/crowdstrike/oldLogs'

splunkHost = 'xxxxx'
authToken = 'xxxxx'

moveDirs = []

def create_directories():
	if not os.path.exists(oldDir):
		os.makedirs(oldDir)

def extract_timestamp(rawLog):
	epochSeconds = re.search('\"timestamp\"\:\"([0-9]{10})([0-9]{3})', rawLog, re.IGNORECASE).group(1)
	epochMilli = re.search('\"timestamp\"\:\"([0-9]{10})([0-9]{3})', rawLog, re.IGNORECASE).group(2)
	epochTime = '{}.{}'.format(epochSeconds, epochMilli)
	return epochTime

def send_logs():
	for subdir, dirs, files in os.walk(rootdir):
		if dirs:
			for directory in dirs:
				dirpath = rootdir + os.sep + directory
				moveDirs.append(dirpath)
		for file in files:
			filepath = subdir + os.sep + file
			if filepath.endswith('.gz'):
				print('Sending {} to Splunk HEC endpoint at {}...'.format(filepath, splunkHost))
				with gzip.open(filepath, 'rt') as f:
					crowdstrike_event = http_event_collector(authToken, splunkHost)
					payload = {}
					payload.update({'index': 'crowdstrike_hec'})
					payload.update({'sourcetype': 'crowdstrike'})
					payload.update({'source': filepath})
					payload.update({'host': 'crowdstrike_replicator'})
					for line in f:
						timestamp = extract_timestamp(line)
						payload.update({'time': timestamp})
						payload.update({'event': line})
						crowdstrike_event.batchEvent(payload)
					crowdstrike_event.flushBatch()

def move_old_directories():
	for directory in moveDirs:
		print('Moving {} to {}...'.format(directory, oldDir))
		shutil.move(directory, oldDir)

create_directories()
send_logs()
move_old_directories()

print('moveDirs: {}'.format(moveDirs))