from app import app
from routes import *
from models import clear_data

if __name__ == '__main__':
    clear_data()
    app.run(ssl_context=('cert/certificate.crt', 'cert/myTest.key')) # jesli nie dziala prosze zakomentowac
    #app.run()                                                       # i odkomentowac ta linie