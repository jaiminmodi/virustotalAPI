from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
import os
from virustotal_api import extract_data


app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/getfile', methods=['GET','POST'])
def getfile():
    if request.method == 'POST':

        # for secure filenames. Read the documentation.
        api_key = request.form['api_key']
        file = request.files['myfile']
        filename = secure_filename(file.filename)

        #Loading data from html page
        file.save(os.path.join(os.getcwd(), filename))
        process_file = os.path.join(os.getcwd(), filename)

        #initiating object of virustotal_api class
        extract_data_object = extract_data(api_key)
        get_data = extract_data_object.add_data(process_file)

        #return the data to a html page in required format
        return render_template('results.html', get_data=get_data)

if __name__ == '__main__':
    app.run()