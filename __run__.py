from app import app
from routes import *
from models import clear_data

if __name__ == '__main__':
    clear_data()
    app.run(host='0.0.0.0')
    #app.run(host='0.0.0.0' , ssl_context=("cert/cert.pem","cert/key.pem"))
