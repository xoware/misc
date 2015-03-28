#!/usr/bin/python3
"""This demonstrates a minimal http upload cgi.
This allows a user to upload up to three files at once.
It is trivial to change the number of files uploaded.

This script has security risks. A user could attempt to fill
a disk partition with endless uploads. 
If you have a system open to the public you would obviously want
to limit the size and number of files written to the disk.
"""
import cgi
import cgitb; cgitb.enable()
import os, sys
import datetime
import json
import mysql.connector

try: # Windows needs stdio set for binary mode.
    import msvcrt
    msvcrt.setmode (0, os.O_BINARY) # stdin  = 0
    msvcrt.setmode (1, os.O_BINARY) # stdout = 1
except ImportError:
    pass


UPLOAD_DIR = "uploads/" + os.environ['REMOTE_ADDR'] +'/'+ datetime.datetime.utcnow().strftime("%Y%m%dT%H%M")


HTML_TEMPLATE = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head><title>Log EK</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
</head><body><h1>EK LOG</h1>
<form action="%(SCRIPT_NAME)s" method="POST" enctype="multipart/form-data">
Status: <input name="status" type="text"><br>
message: <input name="message" type="text"><br>
samba_log: <input name="samba_log" type="text"><br>
<input name="submit" type="submit">
</form>
</body>
</html>"""

def print_status_json(status_str, status_code, message):
  """ Print JSON message and exit """
  print("content-type: application/json\n")  
  j = { 'status_msg':  status_str,
    'status_code' : status_code,
    'verbose_msg' : message }
    
  print(json.dumps(j, sort_keys=True, indent=4))


def print_html_form ():
  """This prints out the html form. Note that the action is set to
      the name of the script which makes this is a self-posting form.
     In other words, this cgi both displays a form and processes it.
  """
  print("content-type: text/html\n")
  print(HTML_TEMPLATE % {'SCRIPT_NAME':os.environ['SCRIPT_NAME']})
  
def log_to_sql(form):
  """
  CREATE USER 'xoware'@'localhost' IDENTIFIED BY 'vpex';
  GRANT INSERT,SELECT ON xo_production.* TO 'xoware'@'localhost';

  """

  try:
    cnx = mysql.connector.connect(user='xoware', database='xo_production', password='vpex')
    cursor = cnx.cursor()
    
    add_log_sql = ("INSERT INTO ExoKey_Programmer_Log "
	    " SET ID=0,  Status='%s', IP_Address='%s', Message='%s', "
	    " Samba_Log='%s', Insert_Date=CURRENT_TIMESTAMP") % \
        (form['status'].value, os.environ['REMOTE_ADDR'],
        form['message'].value, form['samba_log'].value)
#    print_status_json('DEBUG', 1, str(add_log_sql))
#    log_data = (form['status'].value, os.environ['REMOTE_ADDR'],
#        form['message'].value, form['samba_log'].value)
    cursor.execute(add_log_sql)
    cnx.commit()
    cursor.close()
    cnx.close()
    print_status_json('OK', 0, 'OK')
    return
  except BaseException as e:
    t, e = sys.exc_info()[:2]
    print_status_json('EXCEPTION', 1, str(e))
    sys.exit()
  

def save_log ():
  """This saves a file uploaded by an HTML form.
    The form_field is the name of the file input field from the form.
     For example, the following form_field would be "file_1":
           <input name="file_1" type="file">
       The upload_dir is the directory where the file will be written.
       If no file was uploaded or if the field does not exist then
       this does nothing.
  """
  
  form = cgi.FieldStorage()
  if 'status' not in form or 'message' not in form:
    print_html_form()
    return
 
  log_to_sql(form)
  
#    if form['version']:
#  fout = file (os.path.join(upload_dir, 'version'), 'wb')
# fout.write (form['version'].value)
#  fout.close()



save_log()


