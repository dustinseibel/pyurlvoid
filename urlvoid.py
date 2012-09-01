# urlvoid.py
# Dustin Seibel
#
# Script to interact with URLVoid. Requires URLVoid API key.
# See: http://blog.urlvoid.com/urlvoid-api-v2-0/
#
# Changelog:
# - 2012-08-17:  Created. (DJS)
# - 2012-08-22:  Added sub-domain stripping from names. (DJS)
#
# Known issues:
# - API can only handle 250 domains per query. Script should be able to make multiple calls if more than 250 
#   are given.
#
# Copyright (c) 2012 Dustin Seibel.
# All rights reserved.
#
# Redistribution and use in source and binary forms are permitted
# provided that the above copyright notice and this paragraph are
# duplicated in all such forms and that any documentation,
# advertising materials, and other materials related to such
# distribution and use acknowledge that the software was developed
# by the <organization>.  The name of the
# University may not be used to endorse or promote products derived
# from this software without specific prior written permission.
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

import sys
import os
import urllib2
from urlparse import urljoin
from urllib import quote
from datetime import datetime
import time
import csv
import argparse
import xml.etree.ElementTree as ET

# Base API URL
BASE_URL = 'http://api.urlvoid.com/index/exec/'

# API Key
API_KEY = ''

# List CSV columns
CSV_COLUMNS = [
	'domain',
	'detected',
	'last_scan',
	'lists_detected',
]

# Default output delimeter
DEFAULT_DELIM = '\t'

# Sub-domains to strip. These will get auto-stripped from the submitted domain name
SUBS_TO_STRIP = [
	'www',
]

def main(args):
	domain_list = set()

	# Set proxy if needed
	if args.proxy:
		set_proxy(args.proxy)

	# Parse input file if given
	if args.input_file:
		try:
			fin = open(args.input_file, 'rb')
		except IOError:
			print >> sys.stderr, "Error: Cannot open input file."
			sys.exit(1)
		domain_list.update(parse_input(fin))
		fin.close()

	# If no input file given, use command line arguments (or stdin)
	else:
		domain_list.update(parse_input(args.domains))

	# Submit to URLVoid
	res = submit(domain_list)

	# Specify if we need to output a header or not
	if args.no_header:
		header = False
	else:
		header = True

	# Output to file if flag is set
	if args.output_file:
		res.save_csv(args.output_file)

	# If no output file give, output to screen
	elif args.export:
		for t in res.get_csv_tuples(header=header):
			print args.delim.join([str(i) for i in t])

	# Else output in a nice table format
	else:
		output_table(res.get_csv_tuples(header=header), header=header)

def _make_args(**kwargs):
	"""Returns arg list suitable for GET or POST requests"""
	args = []
	for k in kwargs:
		if not kwargs[k]:
			continue
		args.append('%s=%s' % (k, str(kwargs[k])))
	return '&'.join(args)

def _make_domain_list(list_of_domains):
	"""Takes a list of domains and converts it to a string URLVoid expects"""
	uniq_domains = set()
	for d in list_of_domains:
		uniq_domains.add(d.lower().strip())
	return '|'.join(uniq_domains)

def _build_args(list_of_domains, api_key=API_KEY):
	"""Simply builds all the POST vars needed"""
	# Get domains in the proper format
	domains_data = _make_domain_list(list_of_domains)

	# Get args
	args = _make_args(domains=domains_data, api=api_key, go='Check')

	return args

def _call_http(args, base_url=BASE_URL):
	"""Submit API call to URLVoid"""
	req = urllib2.urlopen(base_url, args) 
	resp = req.read()
	return resp

def parse_input(domain_input):
	"""Parses input given into a domain list"""
	domains = set()
	for d in domain_input:
		new_d = d.lower().strip()	

		# Strip sub-domains if flag not set
		if not args.no_strip_subs:
			for s in SUBS_TO_STRIP:
				new_d = new_d.replace('%s.' % s, '')
		if new_d:
			domains.add(new_d)
	return list(domains)

def set_proxy(proxy_addr):
	"""Sets proxy for API calls"""
	proxy_handler = urllib2.ProxyHandler({
		'http': proxy_addr,
		'https': proxy_addr,
	})
	opener = urllib2.build_opener(proxy_handler)
	urllib2.install_opener(opener)

def submit(list_of_domains):
	"""Submit domains to URLVoid"""
	# Build args
	args = _build_args(list_of_domains)

	# Submit HTTP
	resp = _call_http(args)

	# Parse request
	results = VoidResults(resp)

	return results

def unixtime_to_dt(unix_time):
	try:
		return datetime.fromtimestamp(int(unix_time))
	except ValueError:
		return None

class VoidResults(object):
	def __init__(self, xml):
		self.xml = xml
		self.result_dict = {}
		self.parse_xml(self.xml)

	def parse_xml(self, xml):
		"""Parses XML response"""
		# Parse XML
		try:
			et_xml = ET.fromstring(xml)
		except ET.ExpatError:
			print >> sys.stderr, "Error: Cannot parse XML response."
			return False

		# Extract results
		for et_detected in et_xml.getchildren():
			# Get core values
			domain = et_detected.attrib.get('domain')
			info = et_detected.attrib

			# Convert Unix time to datetime
			dt = unixtime_to_dt(info.get('last_scan'))
			if dt:
				info['last_scan'] = dt

			# Convert detected to bool
			if info.get('detected') == '1':
				info['detected'] = True
			else:
				info['detected'] = False

			self.result_dict[domain] = info

	def get_detected_domains(self):
		"""Returns a list of detected domains"""
		domains = set()
		for k, v in self.result_dict.iteritems():
			if v.get('detected'):
				domains.add(k)
		return list(domains)

	def get_csv_tuples(self, columns=CSV_COLUMNS, header=False):
		"""Returns of a list of tuples for results"""
		rows = []

		# Add header if flag is set
		if header:
			rows.append(tuple(CSV_COLUMNS))

		# Iterate over results, add rows of tuples
		for k, v in self.result_dict.iteritems():
			t = []
			for c in columns:
				t.append(v.get(c))
			rows.append(tuple(t))
		return rows

	def save_csv(self, file_path, force_overwrite=False):
		"""Saves a CSV file of results"""
		# See if a file exists and if we can overwrite
		if os.path.exists(file_path) and not force_overwrite:
			print >> sys.stderr, "Error: Cannot save CSV, something is already there. Set flag to overwrite to force this."
			return False

		# Open file for writing and create csv object
		try:
			fout = open(file_path, 'wb')
		except IOError:
			print >> sys.stderr, "Error: Cannot save CSV, cannot open file for writing."
			return False
		csv_writer = csv.writer(fout)

		# Get CSV output and write rows
		rows = self.get_csv_tuples(header=True)
		csv_writer.writerows(rows)
		fout.close()
		return True

def output_table(list_of_iters, header=True, sep='|'):
	# Get the number of columns
	cols = len(list_of_iters[0])

	# Initialize our length map
	len_map = []
	for i in range(0, cols):
		len_map.append(0)

	# For each column, get the max length
	for row in list_of_iters:
		i = 0
		for item in row:
			tmp_len = len(str(item))	
			if tmp_len > len_map[i]:
				len_map[i] = tmp_len
			i += 1
	
	# Now output everything
	first_iter = True
	print '-' * (sum(len_map) + (3 * len(len_map)))
	for row in list_of_iters:
		for i in range(0, cols):
			if sep:
				print sep,
			print str(row[i]).ljust(len_map[i]),
		if sep:
			print sep
		else:
			print

		if header and first_iter:
			print '-' * (sum(len_map) + (3 * len(len_map)))
		first_iter = False
	print '-' * (sum(len_map) + (3 * len(len_map)))
	if header:
		print "%s rows returned" % (len(list_of_iters)-1,)
	else:
		print "%s rows returned" % len(list_of_iters)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='URLVoid Domain Checker')
	parser.add_argument('-k', '--api-key', action='store', default=API_KEY, help='Specify API Key')
	parser.add_argument('-p', '--proxy', action='store', default=None, help='HTTP proxy to use')
	parser.add_argument('-i', '--input-file', action='store', help='File containing domains to check')
	parser.add_argument('-o', '--output-file', action='store', help='Save CSV results to file')
	parser.add_argument('-e', '--export', action='store_true', help='Output to stdout in an exportable/greppable format')
	parser.add_argument('domains', nargs='*', default=sys.stdin, help='Domains to submit')
	parser.add_argument('--no-header', action='store_true', default=False, help='Do not output a header')
	parser.add_argument('-d', '--delim', action='store', default=DEFAULT_DELIM, help='Specify stdout output delimeter')
	parser.add_argument('--no-strip-subs', action='store_true', default=False, help='Do not strip sub-domains (like www)')

	args = parser.parse_args()

	main(args)
