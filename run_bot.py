import datetime
import json
import os
import time

from tweet import post_tweet 

if os.path.exists('cursor.json'):
  cursor = json.load(open('cursor.json'))
else:
  cursor = {}
  
n = 0
cur_n = cursor.get('n', -1)
with open('pg1112.txt') as source:
  for line in source:
    n += 1
    line = line.strip()
    if len(line) == 0 or n <= cur_n:
      continue
    
    post_tweet(line)
    with open('cursor.json', 'w') as save_file:
      json.dump({'n': n}, save_file)
    time.sleep(60)