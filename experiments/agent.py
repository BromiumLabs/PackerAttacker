"""
This scripe should be run in the guest VM with The Packer Attacker in it.
It's a server application waiting for connections from unpack.py
"""

import sys
import os
import subprocess
import zipfile

from bottle import route, run, SimpleTemplate, static_file, post, request



# CONFIGURATION #################
dumps_folder = 'C:\\dumps'
archive_name = 'dumps.zip'
port = 9000
set_port = False
usage_printed  = False
################################

for arg in sys.argv:
	if(set_port):
		#set port to the command line argument
		if(arg.isdigit()):
			if(int(arg) >= 0  or int(arg) <= 65535):
				port = int(arg)
				set_port = False
				break
			else:
				print('-p value must be an integer 0-65535')
				exit()
		else:
			print('-p value must be an integer')
			exit()
		continue
		
	elif(arg == '-p'):
		#Check for setting port argument
		set_port = True
		continue
	
	else:
		if(usage_printed == False and arg != sys.argv[0]):
			print('Usage: agent.py -p [port number]')
		usage_printed = True
		continue


def zipdir(path, zip):
    for root, dirs, files in os.walk(path):
        for file in files:
            zip.write(os.path.join(root, file))

@route('/submit', method='POST')
def submit():

    file = request.files.get('file')

    dst_path = '.'

    if not os.path.exists(file.filename):
        file.save(dst_path)

    subprocess.Popen(['PackerAttacker.exe', file.filename])

    return 'ok'


@route('/retrieve', method='GET')
def retrieve():
    zipf = zipfile.ZipFile(archive_name, 'w')
    zipdir(dumps_folder, zipf)
    zipf.close()
    return static_file(archive_name, root='.')

def main():

    print "Starting server on port %d"%port
    
    run(host='', port=port)


if __name__ == '__main__':
    main()


