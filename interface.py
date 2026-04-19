import os
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

# This tells the computer where to save the files people upload
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/', methods=['GET', 'POST'])
def home():
    packets_to_show = []
    filename = None

    if request.method == 'POST':
        # 1. Get the file from the browser
        uploaded_file = request.files.get('pcap_file')
        
        if uploaded_file and uploaded_file.filename != '':
            # 2. Clean the filename (removes weird characters for safety)
            filename = secure_filename(uploaded_file.filename)
            
            # 3. Save the file so we can read it later
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            uploaded_file.save(filepath)
            
            # This is your dummy data for now
            packets_to_show = [
                {'id': 1, 'src': '192.168.1.10', 'dst': '8.8.8.8', 'proto': 'TCP', 'info': 'HTTPS Request'},
                {'id': 2, 'src': '8.8.8.8', 'dst': '192.168.1.10', 'proto': 'TCP', 'info': 'HTTPS Response'},
                {'id': 3, 'src': '10.0.0.5', 'dst': '10.0.0.1', 'proto': 'ICMP', 'info': 'Ping'}
            ]

    return render_template('index.html', packets=packets_to_show, filename=filename)

if __name__ == '__main__':
    app.run(debug=True)