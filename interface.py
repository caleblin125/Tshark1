import os
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename

# Importing your custom logic modules
import detect_exe
import endpoints

app = Flask(__name__)

# Configuration for file uploads
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/', methods=['GET', 'POST'])
def home():
    # Initialize variables to send to the template
    packets_to_show = []
    alerts_to_show = []
    filename = None

    if request.method == 'POST':
        # 1. Grab the uploaded file from the request
        uploaded_file = request.files.get('pcap_file')
        
        if uploaded_file and uploaded_file.filename != '':
            # 2. Secure and save the file
            filename = secure_filename(uploaded_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(filepath)
            
            # --- 3. Analysis Phase ---

            # A. Get Endpoint Data (for the main table)
            # This calls the function in your endpoints.py
            try:
                packets_to_show = endpoints.get_packet_details(filepath)
            except Exception as e:
                print(f"Error in endpoint analysis: {e}")

            # B. Get Security Alerts (for the alerts tab)
            # This calls the check_exe function in detect_exe.py
            try:
                exe_findings = detect_exe.check_exe(filepath)
                for exe in exe_findings:
                    alerts_to_show.append({
                        "type": "FILE_TRANSFER",
                        "title": "Executable Detected",
                        "detail": f"An EXE file ({exe['filename']}) was found in the network traffic.",
                        "payload": f"Source: {exe['src']}:{exe['sport']} -> Destination: {exe['dst']}:{exe['dport']}"
                    })
            except Exception as e:
                print(f"Error in EXE detection: {e}")

    # 4. Render the page with all collected data
    return render_template(
        'index.html', 
        packets=packets_to_show, 
        alerts=alerts_to_show, 
        filename=filename
    )

if __name__ == '__main__':
    # Setting debug=True allows the server to reload automatically on code changes
    app.run(debug=True)