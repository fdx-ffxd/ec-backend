# ==============================================================================
# ElectraCalc - Entrypoint WSGI para cPanel / Phusion Passenger (Hosting Tradicional)
# ==============================================================================

import sys
import os

# Agregar el directorio actual al path de Python
sys.path.insert(0, os.path.dirname(__file__))

# Importar la aplicación Flask
from server_flask import app as application
