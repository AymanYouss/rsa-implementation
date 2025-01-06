import sys
import os

# Add the root directory to the Python path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from app.flask_app import app

if __name__ == "__main__":
    app.run(debug=True)
