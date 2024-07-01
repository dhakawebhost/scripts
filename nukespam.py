#!/usr/bin/env python
############################################################################## 
# nukespam.py ################################################################
##############################################################################
#
# This script is loosely based on findspam.py, originally by Michael Watters.
# 
# The purpose, basically, was to find a quicker way for findspam to work.  In
# essence, the original findspam was written in such a way that it emulated
# a bash script, in as much as it primarily made calls to other programs.
# Additionally, it did not keep any records internally, so it was only good
# for one pass at the input queue at a time.
#
# The downside to nukespam is that while it is comparable in speed for small
# input queues (and a heck of a lot quicker for any input queue over 8000 or
# so messages), it uses far more memory than findspam, as it keeps an internal
# record of the messages that it is tracking.  This is what enables it to not
# only be quicker for large queues, but it is also what allows it to make
# multiple passes over the same set of data.

AUTHOR = 'dwalters@liquidweb.com'
VERSION = "0.0.8"
FILTERING = 0 # 0 == normal, >0 == specific

import os
import commands
import sys
import re
import glob

def dohelp():
  """ Prints a handy, dandy help message """
  print "nukespam v%s\n\nUsage:\n\tnukespam.py [option]\n\nOptions:\n\t--help\n\t\tShows this message.\n\n\t--spamfu\n\t\tShows possible locations of spam scripts.\n\n\t--by-domain\n\t\tUse only the domain portion of the To and From address.\n\nDefault:\n\n\tAct interactively to assist the user in ridding the input\n\tqueue of spam.\n" % (VERSION)
  sys.exit(0)

# The sort_by_value method was lifted from a ASPN posting that I found on the 
# subject, written by Daniel Schult.  The posting in its entirety can be found
# at http://aspn.activestate.com/ASPN/Python/Cookbook/Recipe/52306

def sort_by_value(d):
  """ Returns the keys of dictionary d sorted by their values """
  items=d.items()
  backitems=[ [v[1],v[0]] for v in items]
  backitems.sort()
  return [ backitems[i][1] for i in range(0,len(backitems))]

def spamfu():
  """ Your spamfu is very mighty """
  cwdlines = {}
  mainlog = open('/var/log/exim_mainlog', 'r')
  try:
    for line in mainlog:
      m=re.match(".*\s(cwd=\/home[0-9]*\S+)\s.*", line)
      if m:
        cwd = m.group(1)
        if cwdlines.has_key(cwd):
          cwdlines[cwd] = cwdlines[cwd] + 1
        else:
          cwdlines[cwd] = 1
  finally:
    mainlog.close()
  sorted_keys = sort_by_value(cwdlines)
  for k in sorted_keys:
    print "%d x %s" % (cwdlines[k], k)
  sys.exit(0)

def get_spool(spooldir = None):
  """Returns the current spool filelist"""
  return glob.glob("%s/*/*-H" % spooldir)

def get_messages(spool = None):
  """Returns the messages hash from the spool filename list"""
  messages = {}
  for f in get_spool(spool):
    if os.path.exists(f):
      msgid = re.match(spool + "[a-zA-Z0-9]/(.*)-H", f).group(1)
      msgfile = re.match("(" + spool + "[a-zA-Z0-9]/.*)-H", f).group(1)
      messages[msgid] = {}
      messages[msgid]["file"] = msgfile
      msock = open(f, "r")
      mdata = msock.read().split("\n")
      msock.close
      for line in mdata:
        m = re.match(".*(Subject: |From: |To: |host_name ) *(.*)", line)
        if m:
          header = m.group(1)
          data = m.group(2)
          if FILTERING == 1:
            if header in ["To: ","From: "]:
              m = re.match(".*@([a-zA-Z0-9.-]+).*", data)
              if m:
                data = m.group(1)
          messages[msgid][header] = data
  return messages

def generate_headers(messages = None):
  """Returns a headers hash from a given set of message information"""
  headers = {"Subject: ":{}, "From: ":{}, "To: ":{}, "host_name ":{}}
  for msgid in messages.keys():
    thekeys = messages[msgid].keys()
    thekeys.remove('file')
    for header in thekeys:
      if headers[header].has_key(messages[msgid][header]):
        headers[header][messages[msgid][header]] += 1
      else:
        headers[header][messages[msgid][header]] = 1
  return headers

def generate_popular(headers = None):
  """Returns a popular hash from a given headers hash"""
  popular = {}
  for header in headers.keys():
    if len(headers[header]) >= 5:
      popular[header] = sort_by_value(headers[header])[-5:]
    elif len(headers[header]) > 0:
      popular[header] = sort_by_value(headers[header])[-(len(headers[header])):]
  return popular

def remove_messages(messages = None, header = None, value = None):
  """Remove messages by header value"""
  killem = []
  for msgid in messages.keys():
    if messages[msgid].has_key(header):
      if messages[msgid][header] == value:
        killem.append(messages[msgid]["file"] + "-H")
        killem.append(messages[msgid]["file"] + "-D")
        killem.append(re.sub('input', 'msglog', messages[msgid]["file"]))
        del messages[msgid]
  for k in killem:
    if os.path.exists(k):
      try:
        os.unlink(k)
      except os.error:
        print "Could not unlink %s" % (k)
  return messages

if "--help" in sys.argv:
  dohelp()
  sys.exit(0)
if "--spamfu" in sys.argv:
  spamfu()
  sys.exit(0)
if "--by-domain" in sys.argv:
  FILTERING=1

standard_headers = ["Subject: ", "From: ", "host_name ", "To: "]
headers = {}
for header in standard_headers:
  headers[header] = {}
option = 0
spool = "/var/spool/exim/input/"

print "Gathering information from the queue ..."
messages = get_messages(spool)
print "Done!\n"

while option != "2":

  headers = generate_headers(messages)
  popular = generate_popular(headers)
  missing_headers = []
  for header in standard_headers:
    if popular.has_key(header):
      print "Most popular %s values" % header
      for k in popular[header]:
        print "%d x \"%s\"" % (headers[header][k], k)
      print ""
    else:
      missing_headers.append(header)
  print "What do you want to do?"
  print "[1] Delete spam"
  print "[2] Exit\n"
  option = raw_input("Enter option number: ")
  if option == "1":
    for header in missing_headers:
      standard_headers.remove(header)
    candidates = [];
    for header in standard_headers:
      if popular.has_key(header):
        candidates.append(popular[header][-1])
    num = 0
    for i in candidates:
      print "[%s] -- %d x \"%s\"" %(num,headers[standard_headers[num]][i],i)
      num = num + 1
        
    print "[X] -- Cancel\n"
    z = raw_input("Which messages to delete? ")
      
    if z.upper() == "X":
      sys.exit(0)

    print "Removing spam (this may take a bit, sorry about the lack of output)..."
    messages = remove_messages(messages,standard_headers[int(z)],candidates[int(z)])
    print "Spam has been eliminated."

sys.exit(0)
