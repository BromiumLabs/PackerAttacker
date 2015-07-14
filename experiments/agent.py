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
################################

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


