#python3
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from siftmtp import SiFT_MTP, SiFT_MTP_Error

class SiFT_UPL_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_UPL:
    def __init__(self, mtp):

        self.DEBUG = False
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        self.size_fragment = 1024
        # --------- STATE ------------
        self.mtp = mtp


    # builds an upload response from a dictionary
    def build_upload_res(self, upl_res_struct):

        upl_res_str = upl_res_struct['file_hash'].hex()
        upl_res_str += self.delimiter + str(upl_res_struct['file_size'])
        return upl_res_str.encode(self.coding)


    # parses an upload response into a dictionary
    def parse_upload_res(self, upl_res):

        upl_res_fields = upl_res.decode(self.coding).split(self.delimiter)
        upl_res_struct = {}
        upl_res_struct['file_hash'] = bytes.fromhex(upl_res_fields[0])
        upl_res_struct['file_size'] = int(upl_res_fields[1])
        return upl_res_struct


    # uploads file at filepath in fragments to the server (to be used by the client)
    def handle_upload_client(self, filepath):
        # 1. Compute size of uploaded file
        # 2. Compute hash of uploaded file
        # 3. Split file into chunks
        # 3.5 Encrypt chunks
        # 4. Upload chunks
        
        file = open(filepath, 'rb')
        byte_count = self.size_fragment
        while byte_count == self.size_fragment:
            chunk = f.read(self.size_fragment)
            
            
            
            byte_count = len(chunk)
            



    # handles a file upload on the server (to be used by the server)
    def handle_upload_server(self, filepath):

        # TODO: implement this function!


