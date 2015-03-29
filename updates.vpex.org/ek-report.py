#!/usr/bin/python3
import datetime
import mysql.connector

cnx = mysql.connector.connect(user='xoware', database='xo_production', password='vpex')
cursor = cnx.cursor()

query = ("SELECT Status, IP_Address, Insert_Date, Message "
    " FROM ExoKey_Programmer_Log "
    " WHERE DATE_SUB(CURDATE(),INTERVAL 2 DAY) <=  Insert_Date")

    
cursor.execute(query)

#print("num_results %d" % (cursor.rowcount))

for (Status, IP_Address, Insert_Date, Message) in cursor:
  print("%20s : %16s : %16s : %s " % (Status, IP_Address, Insert_Date, Message))
  print("----------------------------------------------------------------------------------")

cursor.close()
cnx.close()