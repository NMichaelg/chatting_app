import socket
import threading
import sys
import os
import tqdm
from database import *

connection_list=[]
name_list = []
addr_list=[]
# This list is used to remove connection from the list
clean_list = []
FORMAT="utf-8"
host=socket.gethostbyname(socket.gethostname())
ADDR=(host,3007)

server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
try:
    server.bind(ADDR)
except socket.error as message:
    print('error on server')
    sys.exit()

server.listen()



def on_new_connection(conn,addr):
    connected=True
    while connected:
        request=conn.recv(4096).decode(FORMAT)
        commands = request.split(" ")
        if commands[0] == ":authenticate":
          print(commands)
          state = authenticate(commands[1], commands[2])
          if state:
            name_list.append(commands[1])
            # print(commands[3] + commands[4])
            addr_list.append(commands[3]+commands[4])
            # print(addr_list)
            clean_list.append(addr)
          conn.send(str(state).encode(FORMAT))
        elif commands[0] == ":register":
          print(commands)
          state = add_user(commands[1], commands[2])
          conn.send(str(state).encode(FORMAT))
        elif commands[0] ==":get_list":
            print(commands)
            msg = ""
            for idx, ele in enumerate(name_list):
                msg += f"{ele}-{addr_list[idx]} "
            msg=msg.encode(FORMAT)
            conn.send(msg)
        elif commands[0] == ":disconnect":
            print(addr," disconnected!")
            connection_list.remove(conn)
            # print(name_list)
            # print(addr_list.index(addr))
            clean_idx = clean_list.index(addr)
            clean_list.pop(clean_idx)
            name_list.pop(clean_idx)
            addr_list.pop(clean_idx)
            print("Total connection: ",len(connection_list))
            return
        else:
            continue
    


print("server is running")
while True:
    # toggle = input()
    # print(toggle)
    # if toggle == 1:
    #   server.close()
    conn,addr=server.accept()
    connection_list.append(conn)
    print("HERE")
    # addr_list.append(addr)
    # print(addr_list)
    print("New connection [",addr,"] connected!\n")
    print("Total connection: ",len(connection_list))
    thread=threading.Thread(target=on_new_connection,args=(conn,addr,))
    thread.start()
