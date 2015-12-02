#!/bin/bash

# Simple test for fcrypt (CS 4740/6740: Network Security)
# Amirali Sanatinia (amirali@ccs.neu.edu)

python fcrypt.py -e keys/key_dest.pub keys/key_sender emails/email_2.txt emails/email_2.enc
python fcrypt.py -d keys/key_dest keys/key_sender.pub emails/email_2.enc emails/email_2_dec.txt

if ! diff -q emails/email_2.txt emails/email_2_dec.txt > /dev/null ; then
  echo "FAIL"
  else echo "PASS!"
fi