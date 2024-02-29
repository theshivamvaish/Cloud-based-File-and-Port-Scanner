from flask import Flask, render_template, request
import magic
import os
import subprocess
import nmap

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def scan_file(filepath):
    result = subprocess.run(['clamscan', '--stdout', '--disable-summary', filepath], stdout=subprocess.PIPE)
    return result.stdout.decode('utf-8')

def scan_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-p 1-65535')  # Scan all ports

    open_ports = {}
    for port, port_info in nm[ip]['tcp'].items():
        if port_info['state'] == 'open':
            open_ports[port] = port_info['name']

    return open_ports


def create_upload_folder():
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/', methods=['GET', 'POST'])
def scan():
    create_upload_folder()  # Create upload folder if it doesn't exist

    message = None

    if request.method == 'POST':
        if 'file' in request.files:  # File scanning
            file = request.files['file']
            if file.filename == '':
                message = 'No selected file'
            elif file and allowed_file(file.filename):
                filename = file.filename
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                file_type = magic.from_file(filepath, mime=True)
                message = scan_file(filepath)
                os.remove(filepath)  # Delete the file after scanning
            else:
                message = 'Invalid file type'

        elif 'ip' in request.form:  # Port scanning
            ip = request.form['ip']
            open_ports = scan_ports(ip)
            message = format_port_scan_result(open_ports)

    return render_template('index.html', message=message)

def format_port_scan_result(open_ports):
    formatted_result = "Open ports:\n"
    for port, service in open_ports.items():
        formatted_result += f"Port {port} ({service}): Open\n"
    return formatted_result

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)