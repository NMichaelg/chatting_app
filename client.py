import PySimpleGUI as sg
from database import *
import sys
import threading
import os
import tqdm
import platform

# PEER CODE
import socket 

IP = socket.gethostbyname(socket.gethostname())
PORT = 3007 
ADDR = (IP, PORT)
FORMAT = "utf-8"
DISCONNECT_MSG = ":disconnect"
SIZE = 4096


active_list = {}
conn_list = {}
addr_list= []
name_list =[] 
global_username = ''
conn_idx = 0
global_peer = "No one"
global_log = {}

sg.theme('Bluemono')

start_layout = [
                [sg.Text('Invalid Information',text_color="red", visible=False, key="error")],
                [sg.Text('Username: '), sg.Input()],
                [sg.Text('Password:  '), sg.Input(password_char="*")],
                [sg.Button('Sign in'), sg.Button('Sign up')]]


online_list_layout = [[sg.Text("Online list")],[sg.Listbox(values=[], size=(10, 10), key="friend_list", no_scrollbar = True ,enable_events=True)]]
message_layout = [[sg.Text(f"Chatting with {global_peer}",key='receiver')],
                  [sg.Listbox(values=[], expand_x=True, size=(0,10), key="chat_box", no_scrollbar=False)],
                  [sg.FileBrowse(button_text="Upload", key='file'), sg.Input(key='chat_input'), sg.Button('Send')]]

chat_layout = [[sg.Text(key="username"),sg.Button('Sign out')],[
                sg.Column(message_layout, key="right_col"),sg.Column(online_list_layout, element_justification='c', key="left_col")]]

register_layout = [[sg.Text('Register your account')],
                   [sg.Text('User Existed!',text_color="red", visible=False, key="reg_error")],
                   [sg.Text('New account is created', visible=False, key="signup_success")],
                   [sg.Text('Username: '), sg.Input()],
                   [sg.Text('Password: '), sg.Input(password_char="*")],
                   [sg.Button('Back'),sg.Button('Sign up new account')]]

layout = [[sg.Column(start_layout, key="col_start", element_justification='c'), 
           sg.Column(chat_layout, key="col_chat", visible=False), 
           sg.Column(register_layout, key="col_register", visible=False, element_justification='c')]]


current_layout = "start"
window = sg.Window('Python TCP Chat', layout)
SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 1024 * 4

def send_file(filename,s):
    filesize = os.path.getsize(filename)
    # send the filename and filesize
    s.send("file.msg".encode())        #send identifier as  file sending
    s.send(f"{filename}{SEPARATOR}{filesize}".encode())

    # start sending the file
    progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    with open(filename, "rb") as f:
        while True:
            # read the bytes from the file
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                # file transmitting is done
                f.close()
                break
            # we use sendall to assure transimission in 
            # busy networks
            s.sendall(bytes_read)
            # update the progress bar
            progress.update(len(bytes_read))
    return
def receiver(s):
    # receive the file infos
    # receive using client socket, not server socket
    received = s.recv(BUFFER_SIZE).decode()                        #HERE fixing
    # print(received)
    filename, filesize = received.split(SEPARATOR)
    # remove absolute path if there is
    filename = os.path.basename(filename)
    # convert to integer
    filesize = int(filesize)
    # start receiving the file from the socket
    # and writing to the file stream
    progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)

    if not os.path.exists(global_username):
      os.mkdir(global_username)
    # Check current OS 
    os_name = platform.system()
    folder_seperator = '/' if os_name == 'Linux' else '\\'
    new_filename=f"{global_username}{folder_seperator}"+filename
    # print(new_filename)

    with open(new_filename, "wb") as f:
        while True:
            # read 1024 bytes from the socket (receive)
            bytes_read = s.recv(BUFFER_SIZE)                           #HERER
            if  len(bytes_read)!=BUFFER_SIZE:    
                # nothing is received
                # file transmitting is done
                f.close()
                break
            # write to the file the bytes we just received
            # print(len(bytes_read))
            f.write(bytes_read)
            # update the progress bar
            progress.update(len(bytes_read))
    # print("file rec done") 
    return

def on_new_connection(conn,flag):             # new thread for sending and receving message,file
    connected=True
    while connected:
        if flag==1:
            #recieve message
            msg=conn.recv(4096)
            msg=msg.decode(FORMAT)
            key_list = list(conn_list.keys())
            val_list = list(conn_list.values())
            pos = val_list.index(conn)
            name = key_list[pos]
            if "file.msg" in msg: # If File transfer
                global_log[name].append(f'[{name}] sent a file')
                window['chat_box'].update(values=global_log[global_peer]) 
                receiver(conn)
                continue
            # render message
            global_log[name].append(f'{name} : {msg}')
            window.refresh()
            window['chat_box'].update(values=global_log[global_peer]) 
        else:
            # sending message
            msg=input()   
            msg=msg.encode(FORMAT)
            conn_list[global_peer].send(msg)

# Client connect to central server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port_no = int(input("port : "))
host=socket.gethostbyname(socket.gethostname())                 
client_server_addr=(host,port_no)
print(client_server_addr)
try:
    client.bind(client_server_addr)
except socket.error as message:
    print('error occur')
    sys.exit()
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, 3007)
client.connect(ADDR)
# Thread for sending message
sender=threading.Thread(target=on_new_connection,args=(client,2,))
sender.start()


# listening socket only
LPORT = 0
lclient_addr=(IP,LPORT)
# print(lclient_addr)
lclient=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
try:
    lclient.bind(lclient_addr)
    lclient.listen()
    lclient_addr = lclient.getsockname()
except socket.error as message:
    print('Bind failed. Error Code : '
          + str(message[0]) + ' Message '
          + message[1])
    sys.exit()


def connect_peer():                                     #listening for connection from other peer.
    while True:
        # print("HERE")
        connection,addr=lclient.accept()
        # conn_list.append(connection)
        addr_list.append(addr)        

        identifier=connection.recv(1024).decode(FORMAT) #identifier first connection
        # name_list.append(identifier)                    #name list for active connection
        conn_list[identifier] = connection
        # print("new peer connected: ",identifier)
        global_log[identifier] = []
        # print("CONNETPEER:", global_log)
        #open listen thread only 
        
        new_sender=threading.Thread(target=on_new_connection,args=(connection,1,))      
        new_sender.start()
        
# ---------



def handle_register(username, password):
  print (username + password)
  client.send(f":register {username} {password}".encode(FORMAT))
  state = client.recv(1024).decode(FORMAT)
  return True if state == "True" else False

def handle_login(username, password):
  global current_layout
  global window
  global global_peer
  global client
  # Send the username and password to authenticate
  try:
    client.send(f":authenticate {username} {password} {lclient_addr}".encode(FORMAT))
  except:
    print('error trying to send login request')
  # Server return a string
  state = client.recv(SIZE).decode(FORMAT)
  print("WORKS FINE")
  print("LOGIN: ", state) 
  if state == "False":
    window.Element("error").update(visible=True)
  else:
    global global_username
    # Update the connection_list
    window['col_start'].update(visible=False)
    window.Element("error").update(visible=False)
    current_layout='chat'
    window['col_chat'].update(visible=True)
    global_username = username



def hide_register_layout():
  global current_layout
  global window
  window['col_register'].update(visible=False)
  current_layout = "start"
  window['col_start'].update(visible=True)


def handle_chat_layout(event, values):
  global current_layout
  global global_peer
  # Get online list
  client.send(":get_list".encode(FORMAT))
  addr_list = client.recv(SIZE).decode(FORMAT).strip().split(" ")
  temp_name = []
  # adding online client to online list
  for ele in addr_list:
    [addr_name, addr] = ele.split("-")
    temp_name.append(addr_name)
    if global_username == addr_name or addr_name in active_list:
      continue
    # Parse the message to tuple for chatting later
    tmp = addr.replace('(','').replace(')','').replace(' ','').replace('\'','').split(",")
    tmp[1] = int(tmp[1])
    active_list[f'{addr_name}'] = tuple(tmp)
  # Check if a user is remove 
  for username in active_list.keys():
    if username not in temp_name:
      active_list.pop(username)
      break



  # Update username 
  window['username'].update(f"Hello {values[0]}")
  window['left_col'].Widget.configure(borderwidth=1, relief=sg.DEFAULT_FRAME_RELIEF)
  # Logout 
  if event == "Sign out":
    window['col_chat'].update(visible=False)
    current_layout="start"
    window['col_start'].update(visible=True)
    # Remove user in central server
    client.send(DISCONNECT_MSG.encode(FORMAT)) 
    client.close()
    # Pop it in active list 
    # for idx, user in enumerate(active_list):
    #   for username,_ in user.items():
    #     if username == global_username:
    #       active_list.pop(idx)
          # print(active_list)

  # Get friend list here and update it
  if event == 'friend_list' or event == sg.TIMEOUT_KEY:
    friends = []
    # print(active_list)
    for username in active_list.keys():
      friends.append(username)
    
    # print("FRIENDS: ", friends)

    window['friend_list'].update(values=friends)
    if event == 'friend_list':
      global_peer = "No one" if len(values['friend_list']) == 0 else values['friend_list'][0]
      window['receiver'].update(f"Receiver: {global_peer}")
  # Check if in name list 
  if global_peer != "No one":
    if global_peer not in name_list:
      global_peer = global_peer
      active_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      active_conn.bind((IP, 0))
      try:
        # print("[DEBUG]: ", active_list[global_peer])
        active_conn.connect(active_list[global_peer]) 
        # print("[DEBUG]: ", active_conn)
      except:
        print("[DEBUG]: Error in connection")
      # Add to conn_list 
      conn_list[global_peer] = active_conn
      # Append to name list 
      global_log[global_peer] = []
      name_list.append(global_peer)
      active_conn.send(global_username.encode(FORMAT))
      rec = threading.Thread(target=on_new_connection, args=(active_conn, 1,))
      rec.start()

    if event == "Send":
      if(values['chat_input'] != ''):
        # print("CHAT: ")
        global_log[global_peer].append(f"[{global_username}]: {values['chat_input']}")
        conn_list[global_peer].send(f"{values['chat_input']}".encode(FORMAT))
        window['chat_input']('')
      elif values['file'] != '':
        # print("FILE: ")
        global_log[global_peer].append(f"File sent to {global_peer}")
        send_file(values['file'], conn_list[global_peer])
        
      window.refresh()

    window['chat_box'].update(global_log[global_peer],scroll_to_index=len(global_log))
    window['chat_box'].update(values=global_log[global_peer]) 
    window.refresh()
  






def gui_process():
  global current_layout
  # Main loop for GUI
  while True:
    # window.refresh()
    event, values = window.read(timeout=1000)
    # Update active list when new connection established
    if event == sg.WIN_CLOSED:
        client.send(DISCONNECT_MSG.encode(FORMAT))
        lclient.close()
        client.close()
        break
    elif event == "Sign up":
      window[f'col_{current_layout}'].update(visible=False)
      current_layout = "register"
      window[f'col_register'].update(visible=True)
    # Handle back to login screen
    if event == "Back" and current_layout == "register":
      hide_register_layout()

    # Handle Register 
    if event == "Sign up new account" and current_layout == "register":
      state = handle_register(values[2], values[3])
      if state == True:
        window.Element('signup_success').update(visible=True)
        window.Element("reg_error").update(visible=False)
      else:
        window.Element('signup_success').update(visible=False)
        window.Element("reg_error").update(visible=True)

    if event == "Sign in" and current_layout == "start":
      handle_login(values[0], values[1])

    # Handle chat message
    if current_layout == "chat":
      handle_chat_layout(event, values)
  window.close()
  os.exit()

def chat_pro ():
    connect_peer()
    os._exit(1)

gui=threading.Thread(target=gui_process)
chat_process=threading.Thread(target=chat_pro)
gui.start()
chat_process.start()