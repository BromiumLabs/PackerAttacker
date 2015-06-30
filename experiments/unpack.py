"""
This script is supposed to be run from the host
it will submit the file for unpacking to the VM armed
with The Packer Attacker. It communicates to agent.py
"""

import sys
import os
import subprocess
import struct
import requests
import urllib
import time


# CONFIGURATION #################################
# If you're using VirtualBox just put the name of the VM (not supported)
vm_path = '/path/to/your/vm.vmx'
# IP address and port of your VM (should be accessible from the host)
vm_agent_url = 'http://<VM IP>:<port>'

submission_url = vm_agent_url+'/submit'
retrieval_url = vm_agent_url+'/retrieve'

# If you're using VirtualBox
# vm_manager = 'VBoxManage'
# You might need to include full path if running on Windows
vm_manager = 'vmrun'

# Name of snapshot to restore
snapshot = 'snapshot name'

# vm_type = 'vbox' not supported
vm_type = 'vmware'

# Time to unpack (in seconds)
timeout = 20
###############################################

IMAGE_FILE_DLL = 0x2000



def main():
    if len(sys.argv)!=2:
        exit('Usage: %s <exe>'%sys.argv[0])

    exe = sys.argv[1]

    if not os.path.exists(exe):
        exit('%s does not exist'%exe)

    if os.path.isdir(exe):
        exit('%s is a directory'%exe)

    fd = open(exe, 'rb')
    data = fd.read()
    #fd.close()

    if data[:2]!='MZ':
        exit('%s: Invalide file - MZ header missing'%exe)


    pe_offset = struct.unpack('<H', data[0x3C:0x3E])[0]
        
        
    machine_offset = pe_offset+4
    characteristics_offset = pe_offset+0x16

    machine_val = struct.unpack('<H', data[machine_offset:machine_offset+2])[0]
    characteristics_value = struct.unpack('<H', data[characteristics_offset:characteristics_offset+2])[0]


    if characteristics_value&IMAGE_FILE_DLL:
        exit('%s is a DLL'%exe)

    if machine_val!=0x14c:
        exit('%s is not a 32 bit application'%exe)


    sys.stdout.write('Restoring snapshot and starting the VM...')
    subprocess.call([vm_manager, 'revertToSnapshot', vm_path, snapshot])
    subprocess.call([vm_manager, 'start', vm_path])
    sys.stdout.write('done\n')

    fd.seek(0)

    files = {
        'file': (os.path.basename(exe), fd)
    }

    sys.stdout.write('Submitting...')

    try:
        r = requests.post(submission_url, data=None, files=files)
    except requests.exceptions.ConnectionError as e:
        exit(str(e))

    if r.status_code!=200:
        exit('Failed to submit file for analysis')
    
    sys.stdout.write('done\n')

    sys.stdout.write('Analyzing...')
    time.sleep(timeout)
    sys.stdout.write('done\n')

    sys.stdout.write('Retrieveing the dumps...')
    file = urllib.URLopener()


    dumps_path = exe+'.zip'

    try:
        file.retrieve(retrieval_url, dumps_path)
    except IOError as e:
        exit(str(e))

    sys.stdout.write('done\n')


    print 'Dumps saved at %s'%dumps_path
    print 'Shutting down the VM'

    subprocess.call([vm_manager, 'stop', vm_path])


if __name__ == '__main__':
    main()