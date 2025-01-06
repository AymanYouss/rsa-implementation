import atexit
import base64
import io
import json
import os
import signal
import time
from datetime import datetime, timedelta

import PyPDF2
import pytesseract  # For extracting text from images
from flask import (Flask, redirect, render_template, request, send_file,
                   send_from_directory, session, url_for)
from PIL import Image

from RSA.rsa import RSA
from SecurityAnalysis.rsa_key_management import RSAKeyManager

app = Flask(__name__)
app.secret_key = 'your_secret_key'
#app.permanent_session_lifetime = timedelta(minutes=30)
#rsa = RSA(2048)
key_manager = RSAKeyManager(key_size=2048, expiration_days=30)
KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keys')
rsa = key_manager.rsa 

def ensure_keys_directory():
    """Ensure the keys directory exists"""
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR, exist_ok=True)

def cleanup_keys():
    try:
        for file in [key_manager.public_key_file, key_manager.private_key_file, key_manager.meta_file]:
            if os.path.exists(file):
                os.remove(file)
        if os.path.exists(KEYS_DIR) and not os.listdir(KEYS_DIR):
            os.rmdir(KEYS_DIR)
    except Exception as e:
        print(f"Error during cleanup: {e}")



# Register signal handlers


def init_app():
    """Initialize application state"""
    ensure_keys_directory()
    load_keys()

@app.before_request
def make_session_permanent():
    """Make session permanent but with timeout"""
    #session.permanent = True

def format_key_for_display(key_tuple):
    """Format key tuple for display"""
    if key_tuple and len(key_tuple) == 2:
        return f"{key_tuple[0]}, {key_tuple[1]}"
    return None

def get_template_context():
    """Helper function to get consistent template context with actual RSA keys"""
    expiration_info = None
    try:
        meta_file_path = os.path.join(KEYS_DIR, key_manager.meta_file)
        if os.path.exists(meta_file_path):
            with open(meta_file_path, 'r') as f:
                metadata = json.load(f)
                expiration_time = datetime.fromisoformat(metadata['expiration_time'])
                time_left = expiration_time - datetime.utcnow()
                
                if time_left.total_seconds() <= 0:
                    expiration_info = "Keys have expired - please regenerate"
                else:
                    days = time_left.days
                    hours = time_left.seconds // 3600
                    expiration_info = f"Keys expire in {days} days and {hours} hours"
    except Exception as e:
        expiration_info = "Unable to read key expiration information"

    return {
        'public_key': format_key_for_display(rsa.public_key) if hasattr(rsa, 'public_key') else None,
        'private_key': format_key_for_display(rsa.private_key) if hasattr(rsa, 'private_key') else None,
        'encrypted_message': session.get('encrypted_message'),
        'decrypted_message': session.get('decrypted_message'),
        'error': session.get('error'),
        'expiration_info': expiration_info
    }
@app.route('/')
def index():
    cleanup_session()
    ensure_keys_directory()  # Ensure directory exists before any operation
    load_keys()  # Try to load existing keys
    return render_template('index.html', **get_template_context())

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    ensure_keys_directory()  # Ensure directory exists before generating keys
    cleanup_keys()  # Clean up old keys before generating new ones
    key_manager.generate_and_save_keypair()
    global rsa
    rsa = key_manager.rsa
    session.pop('encrypted_message', None)
    session.pop('decrypted_message', None)
    session.pop('error', None)
    save_keys()
    # Save metadata
    metadata = {
            "creation_time": datetime.utcnow().isoformat(),
            "expiration_time": (datetime.utcnow() + timedelta(days=key_manager.expiration_days)).isoformat(),
            "key_size": key_manager.key_size
        }
    meta_file_path = os.path.join(KEYS_DIR, key_manager.meta_file)

    # Write the metadata to the file
    with open(meta_file_path, 'w') as f:
        json.dump(metadata, f, indent=4)
    

    return render_template('index.html', **get_template_context())
def check_and_rotate_keys():
    if key_manager.is_key_expired():
        key_manager.rotate_keys()
        global rsa
        rsa = key_manager.rsa
def set_error(message):
    session['error'] = message
    session['error_timestamp'] = datetime.utcnow().isoformat()
@app.before_request
def clear_expired_errors():
    """Clear session errors after 7 seconds."""
    error_timestamp = session.get('error_timestamp')
    if error_timestamp:
        # Calculate the time difference
        elapsed_time = datetime.utcnow() - datetime.fromisoformat(error_timestamp)
        if elapsed_time.total_seconds() > 7:
            session.pop('error', None)
            session.pop('error_timestamp', None)
@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    check_and_rotate_keys()
    if not rsa.public_key:
        session['error'] = "Please generate keys first."
        return render_template('index.html', **get_template_context())
    
    message = request.form['message']
    try:
        encrypted_message = rsa.encrypt(message)
        session['encrypted_message'] = str(encrypted_message)
        session.pop('decrypted_message', None)
        session.pop('error', None)
    except Exception as e:
        set_error(f"Encryption error: {str(e)}")
        
    
    return render_template('index.html', **get_template_context())

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    check_and_rotate_keys()
    if not rsa.private_key:
        session['error'] = "Please generate keys first."
        return render_template('index.html', **get_template_context())
    
    try:
        encrypted_message = int(request.form['message'])
        decrypted_message = rsa.decrypt(encrypted_message)
        decrypted_text = decrypted_message.decode('utf-8')
        session['decrypted_message'] = decrypted_text
        session.pop('encrypted_message', None)
        session.pop('error', None)
    except (ValueError, AttributeError) as e:
        set_error("Invalid input for decryption. Please ensure you're entering a valid encrypted number.")
        
    except Exception as e:
        set_error(f"Decryption error: {str(e)}")
      
    
    return render_template('index.html', **get_template_context())

def save_keys():
    """Save RSA keys to files"""
    ensure_keys_directory()  # Ensure directory exists before saving
    try:
        if rsa.public_key:
            with open(os.path.join(KEYS_DIR, 'public_key.txt'), 'w') as public_file:
                public_file.write(f"{rsa.public_key[0]},{rsa.public_key[1]}")
        
        if rsa.private_key:
            with open(os.path.join(KEYS_DIR, 'private_key.txt'), 'w') as private_file:
                private_file.write(f"{rsa.private_key[0]},{rsa.private_key[1]}")
    except Exception as e:
        print(f"Error saving keys: {e}")

def load_keys():
    """Load RSA keys from files"""
    ensure_keys_directory()  # Ensure directory exists before loading
    try:
        public_key_path = os.path.join(KEYS_DIR, 'public_key.txt')
        private_key_path = os.path.join(KEYS_DIR, 'private_key.txt')
        
        if os.path.exists(public_key_path):
            with open(public_key_path, 'r') as public_file:
                n, e = map(int, public_file.read().split(','))
                rsa.public_key = (n, e)
        
        if os.path.exists(private_key_path):
            with open(private_key_path, 'r') as private_file:
                p, q = map(int, private_file.read().split(','))
                rsa.private_key = (p, q)
    except Exception as e:
        print(f"Error loading keys: {e}")
def extract_text_from_file(file):
    """Extract text content from different file types"""
    filename = file.filename
    content_type = file.content_type
    file_bytes = file.read()
    
    # Handle different file types
    if content_type.startswith('image/'):
        # Extract text from image using OCR
        img = Image.open(io.BytesIO(file_bytes))
        text_content = pytesseract.image_to_string(img)
        
    elif content_type == 'application/pdf':
        # Extract text from PDF
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
        text_content = ""
        for page in pdf_reader.pages:
            text_content += page.extract_text()
            
    else:
        # Treat as text file
        text_content = file_bytes.decode('utf-8')
    
    return text_content.strip(), filename

@app.route('/encrypt_file', methods=['POST'])
def encrypt_file():
    if 'file' not in request.files:
        session['error'] = "No file provided"
        return render_template('index.html', **get_template_context())
    
    file = request.files['file']
    if file.filename == '':
        set_error("No file selected")
       
        return render_template('index.html', **get_template_context())
    
    try:
        #
        content_type = file.content_type
        
        # Handle different file types
        if content_type.startswith('image/'):
            
            original_filename = file.filename
            file_bytes = file.read()
            # For images, convert to base64 first
            base64_data = base64.b64encode(file_bytes).decode('utf-8')
            # Add a prefix to identify this as an encrypted image
            data_to_encrypt = f"IMAGE:{content_type}:{base64_data}"
        else:
            # Handle text extraction as before
            #text_content, _ = extract_text_from_file(file)
            text_content, original_filename = extract_text_from_file(file)
            data_to_encrypt = text_content
        
        if not data_to_encrypt:
            set_error("No content could be extracted from the file")
          
            return render_template('index.html', **get_template_context())
        
        # Encrypt the data
        encrypted_data = rsa.encrypt(data_to_encrypt)
        
        # Create in-memory file
        mem_file = io.BytesIO()
        mem_file.write(str(encrypted_data).encode('utf-8'))
        mem_file.seek(0)
        
        # Generate download filename
        download_name = f"encrypted_{original_filename.rsplit('.', 1)[0]}.txt"
        
        # Return file for direct download
        return send_file(
            mem_file,
            mimetype='text/plain',
            as_attachment=True,
            download_name=download_name
        )
        
    except Exception as e:
        set_error(f"Encryption error: {str(e)}")
        
        return render_template('index.html', **get_template_context())

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
   
    if 'file' not in request.files:
        set_error("No file provided")
        
        return render_template('index.html', **get_template_context())
    
    file = request.files['file']
    if file.filename == '':
        set_error( "No file selected")
        return render_template('index.html', **get_template_context())
    
    try:
        # Read encrypted data
        encrypted_data = int(file.read().decode('utf-8'))
        
        # Decrypt the data
        decrypted_data = rsa.decrypt(encrypted_data)
        decrypted_text = decrypted_data.decode('utf-8')
        
        # Check if this is an encrypted image
        if decrypted_text.startswith('IMAGE:'):
            # Split the prefix, content type, and base64 data
            _, content_type, base64_data = decrypted_text.split(':', 2)
            
            # Decode base64 back to binary
            image_data = base64.b64decode(base64_data)
            
            # Create in-memory file with image data
            mem_file = io.BytesIO(image_data)
            mem_file.seek(0)
            
            # Generate download filename with correct extension
            extension = content_type.split('/')[-1]
            original_filename = file.filename
            download_name = f"decrypted_{original_filename.rsplit('.', 1)[0]}.{extension}"
            
            # Return image file for direct download
            return send_file(
                mem_file,
                mimetype=content_type,
                as_attachment=True,
                download_name=download_name
            )
        else:
            # Handle regular text data as before
            mem_file = io.BytesIO()
            mem_file.write(decrypted_text.encode('utf-8'))
            mem_file.seek(0)
            
            # Generate download filename
            original_filename = file.filename
            download_name = f"decrypted_{original_filename.rsplit('.', 1)[0]}.txt"
            
            # Return text file for direct download
            return send_file(
                mem_file,
                mimetype='text/plain',
                as_attachment=True,
                download_name=download_name
            )
        
    except Exception as e:
        session['error'] = f"Decryption error: {str(e)}"
        return render_template('index.html', **get_template_context())
def cleanup_session():
    """Clear all session data"""
    
    session.pop('encrypted_message',None)
   
    session.pop('decrypted_message',None)
    
    session.pop('error',None)

def cleanup():
    """Main cleanup function"""
    cleanup_keys()
    cleanup_session()
# Initialize the app when it starts
init_app()
#atexit.register(cleanup)  
# Register cleanup functions
atexit.register(cleanup)

def signal_handler(signum, frame):
    """Handle termination signals"""
    cleanup()
    #cleanup_keys()
    exit(0)
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)
if __name__ == "__main__":
    # Ensure cleanup happens when the development server reloads
    try:
        app.run(debug=True)
        cleanup()
    finally:
        cleanup()