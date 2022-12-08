#python3

import os
from base64 import b64encode, b64decode
from Crypto.Hash import SHA256
from siftmtp import SiFT_MTP, SiFT_MTP_Error
# TODO: When the appropriate classes for the Upload and Download Protocols
#       are created, un-comment the lines below
#from siftupl import SiFT_UPL, SiFT_UPL_Error
#from siftdnl import SiFT_DNL, SiFT_DNL_Error

class SiFT_CMD_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_CMD:
    def __init__(self, mtp):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        self.cmd_pwd = 'pwd'
        self.cmd_lst = 'lst'
        self.cmd_chd = 'chd'
        self.cmd_mkd = 'mkd'
        self.cmd_del = 'del'
        self.cmd_upl = 'upl'
        self.cmd_dnl = 'dnl'
        self.commands = (self.cmd_pwd, self.cmd_lst, self.cmd_chd,
                         self.cmd_mkd, self.cmd_del,
                         self.cmd_upl, self.cmd_dnl)
        self.res_success = 'success'
        self.res_failure = 'failure'
        self.res_accept =  'accept'
        self.res_reject =  'reject'
        # --------- STATE ------------
        self.mtp = mtp
        self.server_rootdir = None
        self.user_rootdir = None
        self.current_dir = []
        self.filesize_limit = 2**16


    # sets the root directory (to be used by the server)
    def set_server_rootdir(self, server_rootdir):
        self.server_rootdir = server_rootdir


    # sets the root directory of the user (to be used by the server)
    def set_user_rootdir(self, user_rootdir):
        self.user_rootdir = user_rootdir
        # DEBUG
        if self.DEBUG:
            print('User root directory is set to ' + self.user_rootdir)
        # DEBUG

    # sets file size limit for uploads
    def set_filesize_limit(self, limit):
        self.filesize_limit = limit

    # builds a command request from a dictionary
    def build_command_req(self, cmd_req_struct):
        print("in build_command_req ", cmd_req_struct)

        cmd_req_str = cmd_req_struct['command']

        if cmd_req_struct['command'] == self.cmd_chd:
            cmd_req_str += self.delimiter + cmd_req_struct['param_1']

        elif cmd_req_struct['command'] == self.cmd_mkd:
            cmd_req_str += self.delimiter + cmd_req_struct['param_1']

        elif cmd_req_struct['command'] == self.cmd_del:
            cmd_req_str += self.delimiter + cmd_req_struct['param_1']

        elif cmd_req_struct['command'] == self.cmd_upl:
            cmd_req_str += self.delimiter + cmd_req_struct['param_1']
            cmd_req_str += self.delimiter + str(cmd_req_struct['param_2'])
            cmd_req_str += self.delimiter + cmd_req_struct['param_3'].hex()

        elif cmd_req_struct['command'] == self.cmd_dnl:
            cmd_req_str += self.delimiter + cmd_req_struct['param_1']

        return cmd_req_str.encode(self.coding)


    # parses a command request into a dictionary
    def parse_command_req(self, cmd_req):
        cmd_req_fields = cmd_req.decode(self.coding).split(self.delimiter)
        print("in parse commannd req ", cmd_req_fields)

        cmd_req_struct = {}
        cmd_req_struct['command'] = cmd_req_fields[0]

        if cmd_req_struct['command'] == self.cmd_chd:
            cmd_req_struct['param_1'] = cmd_req_fields[1]

        elif cmd_req_struct['command'] == self.cmd_mkd:
            cmd_req_struct['param_1'] = cmd_req_fields[1]

        elif cmd_req_struct['command'] == self.cmd_del:
            cmd_req_struct['param_1'] = cmd_req_fields[1]

        elif cmd_req_struct['command'] == self.cmd_upl:
            cmd_req_struct['param_1'] = cmd_req_fields[1]
            cmd_req_struct['param_2'] = int(cmd_req_fields[2])
            cmd_req_struct['param_3'] = bytes.fromhex(cmd_req_fields[3])

        elif cmd_req_struct['command'] == self.cmd_dnl:
            cmd_req_struct['param_1'] = cmd_req_fields[1]

        return cmd_req_struct


    # builds a command response from a dictionary
    def build_command_res(self, cmd_res_struct):

        cmd_res_str = cmd_res_struct['command']
        cmd_res_str += self.delimiter + cmd_res_struct['request_hash'].hex()
        cmd_res_str += self.delimiter + cmd_res_struct['result_1'] # 'success'/'failure' or 'accept'/'reject'

        if cmd_res_struct['command'] == self.cmd_pwd:
            cmd_res_str += self.delimiter + cmd_res_struct['result_2']

        elif cmd_res_struct['command'] == self.cmd_lst:
            if cmd_res_struct['result_1'] == 'failure':
                cmd_res_str += self.delimiter + cmd_res_struct['result_2']
            else: # 'success'
                cmd_res_str += self.delimiter + b64encode(cmd_res_struct['result_2'].encode(self.coding)).decode(self.coding)

        elif cmd_res_struct['command'] == self.cmd_chd:
            if cmd_res_struct['result_1'] == 'failure':
                cmd_res_str += self.delimiter + cmd_res_struct['result_2']

        elif cmd_res_struct['command'] == self.cmd_mkd:
            if cmd_res_struct['result_1'] == 'failure':
                cmd_res_str += self.delimiter + cmd_res_struct['result_2']

        elif cmd_res_struct['command'] == self.cmd_del:
            if cmd_res_struct['result_1'] == 'failure':
                cmd_res_str += self.delimiter + cmd_res_struct['result_2']

        elif cmd_res_struct['command'] == self.cmd_upl:
            if cmd_res_struct['result_1'] == 'reject':
                cmd_res_str += self.delimiter + cmd_res_struct['result_2']

        elif cmd_res_struct['command'] == self.cmd_dnl:
            if cmd_res_struct['result_1'] == 'reject':
                cmd_res_str += self.delimiter + cmd_res_struct['result_2']
            else: # 'accept'
                cmd_res_str += self.delimiter + str(cmd_res_struct['result_2'])
                cmd_res_str += self.delimiter + cmd_res_struct['result_3'].hex()

        return cmd_res_str.encode(self.coding)


    # parses a command response into a dictionary
    def parse_command_res(self, cmd_res):

        cmd_res_fields = cmd_res.decode(self.coding).split(self.delimiter)

        cmd_res_struct = {}
        cmd_res_struct['command'] = cmd_res_fields[0]
        cmd_res_struct['request_hash'] = bytes.fromhex(cmd_res_fields[1])
        cmd_res_struct['result_1'] = cmd_res_fields[2]

        if cmd_res_struct['command'] == self.cmd_pwd:
            cmd_res_struct['result_2'] = cmd_res_fields[3]

        elif cmd_res_struct['command'] == self.cmd_lst:
            if cmd_res_struct['result_1'] == 'failure':
                cmd_res_struct['result_2'] = cmd_res_fields[3]
            else: # 'success'
                cmd_res_struct['result_2'] = b64decode(cmd_res_fields[3]).decode(self.coding)

        elif cmd_res_struct['command'] == self.cmd_chd:
            if cmd_res_struct['result_1'] == 'failure':
                cmd_res_struct['result_2'] = cmd_res_fields[3]

        elif cmd_res_struct['command'] == self.cmd_mkd:
            if cmd_res_struct['result_1'] == 'failure':
                cmd_res_struct['result_2'] = cmd_res_fields[3]

        elif cmd_res_struct['command'] == self.cmd_del:
            if cmd_res_struct['result_1'] == 'failure':
                cmd_res_struct['result_2'] = cmd_res_fields[3]

        elif cmd_res_struct['command'] == self.cmd_upl:
            if cmd_res_struct['result_1'] == 'reject':
                cmd_res_struct['result_2'] = cmd_res_fields[3]

        elif cmd_res_struct['command'] == self.cmd_dnl:
            if cmd_res_struct['result_1'] == 'reject':
                cmd_res_struct['result_2'] = cmd_res_fields[3]
            else: # 'accept'
                cmd_res_struct['result_2'] = int(cmd_res_fields[3])
                cmd_res_struct['result_3'] = bytes.fromhex(cmd_res_fields[4])

        return cmd_res_struct


    # handles incoming command (to be used by the server)
    def receive_command(self):

        if (not self.server_rootdir) or (not self.user_rootdir):
            raise SiFT_CMD_Error('Root directory must be set before any file operations')

        # trying to receive a command request
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_CMD_Error('Unable to receive command request --> ' + e.err_msg)

        # DEBUG
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG

        if msg_type != self.mtp.type_command_req:
            raise SiFT_CMD_Error('Command request expected, but received something else')

        # computing hash of request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # processing command request
        try:
            cmd_req_struct = self.parse_command_req(msg_payload)
        except:
            raise SiFT_CMD_Error('Parsing command request failed')

        if cmd_req_struct['command'] not in self.commands:
            raise SiFT_CMD_Error('Unexpected command received')

        # executing command
        cmd_res_struct = self.exec_cmd(cmd_req_struct, request_hash)

        # building a command response
        msg_payload = self.build_command_res(cmd_res_struct)

        # DEBUG
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG

        # trying to send command response
        try:
            self.mtp.send_msg(self.mtp.type_command_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_CMD_Error('Unable to send command response --> ' + e.err_msg)

        # if upload command was accepted, then execute upload
        if cmd_res_struct['command'] == self.cmd_upl and cmd_res_struct['result_1'] == self.res_accept:
            try:
                self.exec_upl(cmd_req_struct['param_1'])
            except SiFT_UPL_Error as e:
                raise SiFT_UPL_Error(e.err_msg)

        # if download command was accepted, then execute download
        if cmd_res_struct['command'] == self.cmd_dnl and cmd_res_struct['result_1'] == self.res_accept:
            try:
                self.exec_dnl(cmd_req_struct['param_1'])
            except SiFT_DNL_Error as e:
                raise SiFT_DNL_Error(e.err_msg)


    # builds and sends command to server (to be used by the client)
    def send_command(self, cmd_req_struct):
        # print("in send_command ", cmd_req_struct)

        # building a command request
        msg_payload = self.build_command_req(cmd_req_struct)
        # print("message payload", msg_payload)

        # DEBUG
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG

        # trying to send command request
        try:
            self.mtp.send_msg(self.mtp.type_command_req, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_CMD_Error('Unable to send command request --> ' + e.err_msg)

        # computing hash of sent request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # trying to receive a command response
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_CMD_Error('Unable to receive command response --> ' + e.err_msg)

        # DEBUG
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG

        if msg_type != self.mtp.type_command_res:
            raise SiFT_CMD_Error('Command response expected, but received something else')

        # processing command response
        try:
            # print(msg_payload)
            cmd_res_struct = self.parse_command_res(msg_payload)
            # print(cmd_res_struct)
        except:
            raise SiFT_CMD_Error('Parsing command response failed')

        # checking request_hash receiveid in the command response
        if cmd_res_struct['request_hash'] != request_hash:
            raise SiFT_CMD_Error('Verification of command response failed')

        return cmd_res_struct

# -----------------------------------------------------------------------------------------
# file operations on the server
# -----------------------------------------------------------------------------------------

    # checks file or directory name for special characters
    def check_fdname(self, fdname):

        if not fdname: return False
        if fdname[0] == '.': return False
        for c in fdname:
            if not c.isalnum():
                if c not in ('-', '_', '.'): return False
        return True


    # execute command
    def exec_cmd(self, cmd_req_struct, request_hash):
        print("in exec_cmd ", cmd_req_struct)

        cmd_res_struct = {}
        cmd_res_struct['command'] = cmd_req_struct['command']
        cmd_res_struct['request_hash'] = request_hash

        # pwd
        if cmd_req_struct['command'] == self.cmd_pwd:
            cmd_res_struct['result_1'] = self.res_success
            cmd_res_struct['result_2'] = '/'.join(self.current_dir) + '/'

        # lst
        elif cmd_req_struct['command'] == self.cmd_lst:
            path = self.server_rootdir + self.user_rootdir + '/'.join(self.current_dir)
            print("HERE: ",path)
            if os.path.exists(path): 
                dirlist_str = ''
                with os.scandir(path) as dirlist:
                    for f in dirlist:
                        if not f.name.startswith('.'):
                            if f.is_file(): dirlist_str += f.name + '\n'
                            elif f.is_dir(): dirlist_str += f.name + '/\n'
                if dirlist_str and dirlist_str[-1] == '\n': dirlist_str = dirlist_str[:-1]
                cmd_res_struct['result_1'] = self.res_success
                cmd_res_struct['result_2'] = dirlist_str
            else:
                cmd_res_struct['result_1'] = self.res_failure
                cmd_res_struct['result_2'] = 'Operation failed due to local error on server'

        # chd
        elif cmd_req_struct['command'] == self.cmd_chd:
            dirname = cmd_req_struct['param_1']
            if dirname == '..':
                if not self.current_dir: # we are in user root dir
                    cmd_res_struct['result_1'] = self.res_failure
                    cmd_res_struct['result_2'] = 'Cannot change to directory outside of the user root directory'
                else:
                    path = self.server_rootdir + self.user_rootdir + '/'.join(self.current_dir[:-1])
                    if not os.path.exists(path):
                        cmd_res_struct['result_1'] = self.res_failure
                        cmd_res_struct['result_2'] = 'Directory does not exist'
                    else:
                        self.current_dir = self.current_dir[:-1]
                        cmd_res_struct['result_1'] = self.res_success
            else:
                if not self.check_fdname(dirname):
                    cmd_res_struct['result_1'] = self.res_failure
                    cmd_res_struct['result_2'] = 'Directory name is empty, starts with . or contains unsupported characters'
                else:
                    path = self.server_rootdir + self.user_rootdir + '/'.join(self.current_dir)
                    if path[-1] == '/': path += dirname
                    else: path += '/' + dirname
                    if not os.path.exists(path):
                        cmd_res_struct['result_1'] = self.res_failure
                        cmd_res_struct['result_2'] = 'Directory does not exist'
                    else:
                        self.current_dir.append(dirname)
                        cmd_res_struct['result_1'] = self.res_success

        # mkd
        elif cmd_req_struct['command'] == self.cmd_mkd:
            dirname = cmd_req_struct['param_1']
            if not self.check_fdname(dirname):
                cmd_res_struct['result_1'] = self.res_failure
                cmd_res_struct['result_2'] = 'Directory name is empty, starts with . or contains unsupported characters'
            else:
                path = self.server_rootdir + self.user_rootdir + '/'.join(self.current_dir)
                if path[-1] == '/': path += dirname
                else: path += '/' + dirname
                if os.path.exists(path):
                    cmd_res_struct['result_1'] = self.res_failure
                    cmd_res_struct['result_2'] = 'Directory already exists'
                else:
                    try:
                        os.mkdir(path)
                    except:
                        cmd_res_struct['result_1'] = self.res_failure
                        cmd_res_struct['result_2'] = 'Creating directory failed'
                    else:
                        cmd_res_struct['result_1'] = self.res_success

        # del
        elif cmd_req_struct['command'] == self.cmd_del:
            fdname = cmd_req_struct['param_1']
            if not self.check_fdname(fdname):
                cmd_res_struct['result_1'] = self.res_failure
                cmd_res_struct['result_2'] = 'File name or directory name is empty, starts with . or contains unsupported characters'
            else:
                path = self.server_rootdir + self.user_rootdir + '/'.join(self.current_dir)
                if path[-1] == '/': path += fdname
                else: path += '/' + fdname
                if not os.path.exists(path):
                    cmd_res_struct['result_1'] = self.res_failure
                    cmd_res_struct['result_2'] = 'File or directory does not exist'
                else:
                    if os.path.isdir(path): # remove directory
                        try:
                            os.rmdir(path)
                        except:
                            cmd_res_struct['result_1'] = self.res_failure
                            cmd_res_struct['result_2'] = 'Removing directory failed'
                        else:
                            cmd_res_struct['result_1'] = self.res_success
                    elif os.path.isfile(path): # remove file
                        try:
                            os.remove(path)
                        except:
                            cmd_res_struct['result_1'] = self.res_failure
                            cmd_res_struct['result_2'] = 'Removing file failed'
                        else:
                            cmd_res_struct['result_1'] = self.res_success
                    else:
                        cmd_res_struct['result_1'] = self.res_failure
                        cmd_res_struct['result_2'] = 'Object is not a file or directory'

        # upl
        elif cmd_req_struct['command'] == self.cmd_upl:
            # DONE
            # TODO- : Implement the handling of the upl command here...
            # HINTS:
            #   - take the filename, filesize, and filehash from the command parameter fields
            #     param_1, param_2, and param_3, respectively
            #   - check that the filename is not empty, does not start with . and does not
            #     contain unsupported characters (use self.check_fdname())
            #   - check that the filesize does not exceed self.filesize_limit
            #   - if all checks succeed, then the response should be 'accept'
            #   - otherwise the response should be 'reject' with an appropriate error message

            filename = cmd_req_struct['param_1']
            filesize = cmd_req_struct['param_2']
            filehash = cmd_req_struct['param_3']

            if not self.check_fdname(filename):
                cmd_res_struct['result_1'] = self.res_reject
                cmd_res_struct['result_2'] = 'Filename is either empty, contains special characters, or starts with .'
            else:
                if filesize > filesize_limit:
                    cmd_res_struct['result_1'] = self.res_reject
                    cmd_res_struct['result_2'] = 'The file is to large to be uploaded'
                else:
                    cmd_res_struct['result_1'] = self.res_accept


        # dnl
        elif cmd_req_struct['command'] == self.cmd_dnl:
            # DONE i think
            # TODO: Implement the handling of the dnl command here...
            # HINTS:
            #   - take the filename from the command parameter field param_1
            #   - check that the filename is not empty, does not start with . and does not
            #     contain unsupported characters (use self.check_fdname())
            #   - check that the filename actually refers to an existing file (and not a directory)
            #   - compute the SHA-256 hash of the file content and determine the size of the file (in bytes)
            #     (for the hashing, open the file, read its content, and hash it)
            #   - if all checks were successful, then fill in the fields of the response structure
            #     with the size and the hash, and respond with 'accept'
            #   - otherwise the response should be 'reject' with an appropriate error message

            filename = cmd_req_struct['param_1']
            if not self.check_fdname(filename):
                cmd_res_struct['result_1'] = self.res_failure
                cmd_res_struct['result_2'] = 'Filename is either empty, contains special characters, or starts with .'
            else:
                path = self.server_rootdir + self.user_rootdir + '/'.join(self.current_dir)
                if path[-1] == '/': path += filename
                else: path += '/' + filename
                if not os.path.exists(path):
                    cmd_res_struct['result_1'] = self.res_reject
                    cmd_res_struct['result_2'] = 'File or directory does not exist'
                else:
                    hash_fn = SHA256.new()
                    file = open(path, "rb")
                    byte_count = 1024
                    filesize = 0
                    while bytes_count == 1024:
                        chunk = f.read(1024)
                        byte_count = len(chunk)
                        filesize += byte_count
                        hash_fn.update(chunk)
                    filehash = hash_fn.digest()
                    cmd_res_struct['result_1'] = self.res_accept
                    cmd_res_struct['result_2'] = filesize
                    cmd_res_struct['result_3'] = filehash


        return cmd_res_struct


    # execute upload
    def exec_upl(self, filename):
        # DONE (I think)
        # TODO: remove pass above and implement the upload operation here
        # HINTS:
        #   - check that the filename is not empty, does not start with . and does not
        #     contain unsupported characters (use self.check_fdname())
        #   - create an instance of the Upload Protocol class (SiFT_UPL), and use it to handle
        #     the file upload
        #   - you should pass self.mtp to the constructor of SiFT_UPL
        #   - you may pass the filename or the filepath where the uploaded file should be saved
        #     to the created Uoload Protocol object (instance of SiFT_UPL)
        #   - handle potential errors as needed...

        if not self.check_fdname(filename):
            raise SiFT_UPL_Error('Filename is either empty, contains special characters, or starts with .')
        else:
            path = self.server_rootdir + self.user_rootdir + '/'.join(self.current_dir)
            if path[-1] == '/': path += filename
            else: path += '/' + filename
            upl_protocol = SiFT_UPL(self.mtp)
            upl_protocol.handle_upload_server(filepath)


    # execute download
    def exec_dnl(self, filename):
        # DONE (I think)
        # TODO: remove pass above and implement the download operation here
        # HINTS:
        #   - check that the filename is not empty, does not start with . and does not
        #     contain unsupported characters (use self.check_fdname())
        #   - locate the object referred by the filename and check that it
        #     actually exists and it is not a directory
        #   - create an instance of the Download Protocol class (SiFT_DNL), and use it to handle
        #     the file download
        #   - you should pass self.mtp to the constructor of SiFT_DNL
        #   - you may pass the filename or the filepath of the file to be downloaded to the
        #     created Download Protocol object (instance of SiFT_DNL)
        #   - handle potential errors as needed...

        if not self.check_fdname(filename):
            raise SiFT_DNL_Error('Filename is either empty, contains special characters, or starts with .')
        else:
            path = self.server_rootdir + self.user_rootdir + '/'.join(self.current_dir)
            if path[-1] == '/': path += filename
            else: path += '/' + filename
            if not os.path.exists(path):
                raise SiFT_DNL_Error('Filepath does not exist')
            elif not os.path.isfile(filepath):
                raise SiFT_DNL_Error('Filepath must lead to a file, not a directory')
            else:
                dnl_protocol = SiFT_DNL(self.mtp)
                dnl_protocol.handle_download_server(filepath)
