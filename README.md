# Virustotal API
---


__Structure of the project:__
```
.
├── ...
├── static                    
│   ├── style.css          		   #Reformat the output		
│── templates					   
│   ├── index.html                 #html for rendering input
│   ├── results.html               #html for rendering output
│── application.py	               #Server side file for collecting data
│── virustotal_api.py	           #Server side api for making VT api calls
│── sqldb.py	                   #Server side script for adding/fetching data from sql
│── requirements.txt	           #To install the required packages
```

# Instruction

## Environment

For the implementation of the project, following technologies have been used - Windows, Python, Mysql

1. Please clone the repository & setup virtual environment

```
git clone https://github.com/jaiminmodi/virustotalAPI.git
cd virustotalAPI
virtualenv virustotalAPI
./virustotalAPI/Scripts/activate
```

2. Please install the required packages by executing the following line.

```
pip install -r requirements.txt  #(or in Windows - sometimes python -m pip install -r requirements.txt )
```

3. Start the application with:

```
python3 application.py
```

And visit http://localhost:5000. Please enter the Virustotal API key and batchfile in .txt format.

Please note that the application needs to have permission to bind to the network interfaces.

# Enhancements

1. Using websockets for asynchronous result update in the results.html page. This would require some code changes as the packages will change.

2. In the current project, multithreading can be implemented for quicker results. 

3. Currently the sqldb.py does not have its functionality connected to virustotal_api.py file. 