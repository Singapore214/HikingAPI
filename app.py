from flask import Flask, jsonify, request, abort
from flask_cors import CORS
import jwt
import datetime
import logging
import hashlib
import secrets
import json
from cryptography.fernet import Fernet
from functools import wraps  # Import wraps from functools

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests

# Generate a secure secret key (32 bytes)
SECRET_KEY = secrets.token_hex(32)
JWT_EXPIRATION_DELTA = 3600  # Token expiration in seconds

# Encryption key (use the sample key)
ENCRYPTION_KEY = b'0vON1A8TcCkp8zJ8J_p28oc4_GMjpO53VcVkdJxyl10='
fernet = Fernet(ENCRYPTION_KEY)

def decrypt_file(encrypted_file_path, encryption_key):
    fernet = Fernet(encryption_key)
    with open(encrypted_file_path, 'rb') as enc_file:
        encrypted_data = enc_file.read()
        try:
            decrypted_data = fernet.decrypt(encrypted_data)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            return ""

def encrypt_file(file_path, data, encryption_key):
    fernet = Fernet(encryption_key)
    encrypted_data = fernet.encrypt(data.encode('utf-8'))
    with open(file_path, 'wb') as enc_file:
        enc_file.write(encrypted_data)

def load_credentials():
    try:
        decrypted_data = decrypt_file('credentials.json.enc', ENCRYPTION_KEY)
        if decrypted_data:
            return json.loads(decrypted_data)
        else:
            return {}
    except json.JSONDecodeError:
        print("Error decoding JSON from decrypted data.")
        return {}

def save_credentials(credentials):
    data = json.dumps(credentials, indent=4)
    encrypt_file('credentials.json.enc', data, ENCRYPTION_KEY)

USER_CREDENTIALS = load_credentials()

# Logging configuration
logging.basicConfig(level=logging.INFO)

def generate_token():
    return jwt.encode({
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXPIRATION_DELTA)},
        SECRET_KEY, algorithm='HS256')

# The token_required decorator now properly wraps the function
def token_required(f):
    @wraps(f)  # Use wraps to preserve the original function name
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            abort(403, description="Token is missing")
        try:
            jwt.decode(token.replace('Bearer ', ''), SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            abort(403, description="Token has expired")
        except jwt.InvalidTokenError:
            abort(403, description="Invalid token")
        return f(*args, **kwargs)
    return decorated_function

@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.json
    if not data:
        abort(400, description="No user data provided")
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        abort(400, description="Username and password are required")
    
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    USER_CREDENTIALS[username] = hashed_password
    save_credentials(USER_CREDENTIALS)
    
    return jsonify({'message': 'User added successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    auth = request.json
    if not auth:
        abort(400, description="No credentials provided")
    
    username = auth.get('username')
    password = auth.get('password')
    
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == hashed_password:
        tokens = [generate_token() for _ in range(5)]
        return jsonify({'tokens': tokens})
    else:
        abort(401, description="Invalid credentials")

@app.route('/protected', methods=['GET'])
@token_required
def protected():
    return jsonify({'message': 'This is a protected route'})

@app.route('/suggest_hikes', methods=['POST'])
@token_required
def suggest_hikes():
    # Example data - replace with actual hike suggestion logic
    suggested_hikes = [
        {
    "difficulty": "moderate",
    "distance": "8.4",
    "id": "9f1d835d-dc77-44a5-9234-5ef0a7a6a9d5",
    "location": "Blue Mountains, NSW",
    "weatherlocation": "-33.7365,150.3107",
    "name": "National Pass",
    "rating": "4.7",
    "maplink": "https://maps.apple.com/?address=Blue%20Mountains%20National%20Park%20NSW%202787,%20Australia&auid=8899488025313741809&ll=-33.725419,150.368811&lsp=9902&q=National%20Pass",
    "desc": "The National Pass in Blue Mountains, NSW, is a moderately difficult trail featuring stunning cliffside views and historic staircases carved into the rock.",
    "imagepreview": "https://www.nationalparks.nsw.gov.au/-/media/npws/images/parks/blue-mountains-national-park/katoomba-area/national-pass/national-pass-walk-06.jpg",
    "isDogFriendly": True,
    "imagecontextpreviews": [
      "https://www.nationalparks.nsw.gov.au/-/media/npws/images/parks/blue-mountains-national-park/katoomba-area/national-pass/national-pass-walk-06.jpg",
      "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.truebluemountains.com.au%2Fnational-pass-wentworth-falls%2F&psig=AOvVaw1ShysTwNR4os1zKDLLGHnW&ust=1725032159150000&source=images&cd=vfe&opi=89978449&ved=0CBQQjRxqFwoTCIjpmtrDmogDFQAAAAAdAAAAABAE",
      "https://dynamic-media-cdn.tripadvisor.com/media/photo-o/06/7a/53/0f/the-view-from-valley.jpg?w=1200&h=-1&s=1",
      "https://i0.wp.com/seektoseamore.com/wp-content/uploads/2018/06/P1010999.jpg?resize=775%2C581&ssl=1",
      "https://bushwalkingnsw.com/walk/985/20140906104310_650d_03521.jpg"
    ],
    "route": [
      {
        "latitude": -33.7365,
        "longitude": 150.3107
      },
      {
        "latitude": -33.7350,
        "longitude": 150.3090
      },
      {
        "latitude": -33.7335,
        "longitude": 150.3075
      },
      {
        "latitude": -33.7320,
        "longitude": 150.3060
      },
      {
        "latitude": -33.7310,
        "longitude": 150.3045
      },
      {
        "latitude": -33.7325,
        "longitude": 150.3030
      },
      {
        "latitude": -33.7340,
        "longitude": 150.3015
      },
      {
        "latitude": -33.7355,
        "longitude": 150.3000
      },
      {
        "latitude": -33.7370,
        "longitude": 150.3015
      },
      {
        "latitude": -33.7385,
        "longitude": 150.3030
      },
      {
        "latitude": -33.7370,
        "longitude": 150.3045
      },
      {
        "latitude": -33.7355,
        "longitude": 150.3060
      },
      {
        "latitude": -33.7340,
        "longitude": 150.3075
      },
      {
        "latitude": -33.7335,
        "longitude": 150.3090
      },
      {
        "latitude": -33.7350,
        "longitude": 150.3105
      },
      {
        "latitude": -33.7365,
        "longitude": 150.3107
      }
    ]
  },
  {
    "difficulty": "easy",
    "distance": "6.0",
    "id": "8c2dfb5f-8a3d-4f75-bc2b-02918b5d4328",
    "location": "Mornington Peninsula, VIC",
    "weatherlocation": "-38.4928,144.8641",
    "name": "Cape Schanck Lighthouse Walk",
    "rating": "4.6",
    "maplink": "https://maps.apple.com/?address=Mornington%20Peninsula%20National%20Park,%20Cape%20Schanck%20VIC%203939,%20Australia&ll=-38.495306,144.888361&q=Mornington%20Peninsula%20National%20Park",
    "desc": "Cape Schanck Lighthouse Walk in Mornington Peninsula, VIC, is an easy trail that takes you to the iconic lighthouse, offering breathtaking coastal views.",
    "imagepreview": "https://www.parks.vic.gov.au/-/media/project/pv/main/parks/images/places-to-see/mornington-peninsula-national-park/lighthouse-2-cape-schank-mornington-peninsula-national-park-1920x1124.jpg?rev=320a57ed43e345189315515a43764561",
    "isDogFriendly": False,
    "imagecontextpreviews": [
      "https://www.parks.vic.gov.au/-/media/project/pv/main/parks/images/places-to-see/mornington-peninsula-national-park/lighthouse-2-cape-schank-mornington-peninsula-national-park-1920x1124.jpg?rev=320a57ed43e345189315515a43764561",
      "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwalkingmaps.com.au%2Fwalk%2F4009&psig=AOvVaw0cpHB75c55znoPFNuzJJq6&ust=1725032544353000&source=images&cd=vfe&opi=89978449&ved=0CBQQjRxqFwoTCMiXlpLFmogDFQAAAAAdAAAAABAJ",
      "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.travelsewhere.net%2Fwalking-cape-schanck-victoria%2F&psig=AOvVaw0cpHB75c55znoPFNuzJJq6&ust=1725032544353000&source=images&cd=vfe&opi=89978449&ved=0CBQQjRxqFwoTCMiXlpLFmogDFQAAAAAdAAAAABAR",
      "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.visitmorningtonpeninsula.org%2Fplaces-to-see%2Ftowns-villages%2Fcape-schanck&psig=AOvVaw0cpHB75c55znoPFNuzJJq6&ust=1725032544353000&source=images&cd=vfe&opi=89978449&ved=0CBQQjRxqFwoTCMiXlpLFmogDFQAAAAAdAAAAABAZ",
      "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.racv.com.au%2Froyalauto%2Ftravel%2Fvictoria%2Fbest-walks-near-racv-resorts.html&psig=AOvVaw0cpHB75c55znoPFNuzJJq6&ust=1725032544353000&source=images&cd=vfe&opi=89978449&ved=0CBQQjRxqFwoTCMiXlpLFmogDFQAAAAAdAAAAABAh"
    ],
    "route": [
      {
        "latitude": -38.4928,
        "longitude": 144.8641
      },
      {
        "latitude": -38.4950,
        "longitude": 144.8660
      },
      {
        "latitude": -38.4972,
        "longitude": 144.8680
      },
      {
        "latitude": -38.4967,
        "longitude": 144.8699
      },
      {
        "latitude": -38.4945,
        "longitude": 144.8685
      },
      {
        "latitude": -38.4928,
        "longitude": 144.8670
      },
      {
        "latitude": -38.4928,
        "longitude": 144.8641
      }
    ]
  },
  {
    "difficulty": "hard",
    "distance": "10.2",
    "id": "fc6d2b7c-469a-4a5a-81d7-11d9ec817b78",
    "location": "Grampians, VIC",
    "weatherlocation": "-37.1497,142.5205",
    "name": "The Pinnacle Walk",
    "rating": "4.9",
    "maplink": "https://maps.apple.com/?address=Halls%20Gap%20VIC%203381,%20Australia&auid=1734491250711842809&ll=-37.150594,142.503018&lsp=9902&q=The%20Pinnacle%20walks",
    "desc": "The Pinnacle Walk in Grampians, VIC, is a challenging trail that rewards hikers with panoramic views from the top of the Pinnacle.",
    "imagepreview": "https://www.visitvictoria.com/-/media/images/grampians/things-to-do/nature-and-wildlife/the-pinnacle/the-pinnacle_gra-u_918098_1150x863.jpg?ts=20240503020151",
    "isDogFriendly": False,
    "imagecontextpreviews": [
      "https://www.visitvictoria.com/-/media/images/grampians/things-to-do/nature-and-wildlife/the-pinnacle/the-pinnacle_gra-u_918098_1150x863.jpg?ts=20240503020151"
    ],
    "route": [
      {
        "latitude": -37.1497,
        "longitude": 142.5205
      },
      {
        "latitude": -37.1475,
        "longitude": 142.5220
      },
      {
        "latitude": -37.1458,
        "longitude": 142.5233
      },
      {
        "latitude": -37.1440,
        "longitude": 142.5225
      },
      {
        "latitude": -37.1450,
        "longitude": 142.5205
      },
      {
        "latitude": -37.1497,
        "longitude": 142.5205
      }
    ]
  },
  {
    "difficulty": "moderate",
    "distance": "7.5",
    "id": "b7dcd4f3-9b41-4f84-bdef-1c4d5a9c94b2",
    "location": "Cradle Mountain, TAS",
    "weatherlocation": "-41.6467,145.9374",
    "name": "Dove Lake Circuit",
    "rating": "4.8",
    "maplink": "https://maps.apple.com/?address=Dove%20Lake%20Circuit,%20Cradle%20Mountain%20TAS%207306,%20Australia&auid=2703482302698274460&ll=-41.661334,145.959033&lsp=9902&q=Dove%20Lake%20Circuit",
    "desc": "Dove Lake Circuit in Cradle Mountain, TAS, is a moderate trail circling Dove Lake, providing picturesque views of Cradle Mountain and lush landscapes.",
    "isDogFriendly": True,
    "imagepreview": "https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhnHqDNJ_GBmVWigbzer6DR0qwcnyFcr2foVK9BgrrtDXI5XJlxjyCGCfkh8b1TvXWOJXlXUrSrxcUmIzj1wTy3F32mIID3L_krJb65qxGkftaotC0s0hZq9g4gmgQUYF-Fn4GgUl3ZG70/s1600/DSC06553.JPG",
    "imagecontextpreviews": [
      "https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhnHqDNJ_GBmVWigbzer6DR0qwcnyFcr2foVK9BgrrtDXI5XJlxjyCGCfkh8b1TvXWOJXlXUrSrxcUmIzj1wTy3F32mIID3L_krJb65qxGkftaotC0s0hZq9g4gmgQUYF-Fn4GgUl3ZG70/s1600/DSC06553.JPG"
    ],
    "route": [
      {
        "latitude": -41.6467,
        "longitude": 145.9374
      },
      {
        "latitude": -41.6480,
        "longitude": 145.9380
      },
      {
        "latitude": -41.6500,
        "longitude": 145.9400
      },
      {
        "latitude": -41.6520,
        "longitude": 145.9390
      },
      {
        "latitude": -41.6510,
        "longitude": 145.9370
      },
      {
        "latitude": -41.6467,
        "longitude": 145.9374
      }
    ]
  },
  {
    "difficulty": "easy",
    "distance": "4.5",
    "id": "efa6bc48-eae8-4533-b3e0-6e592c2fa6ab",
    "location": "Dandenong Ranges, VIC",
    "weatherlocation": "-37.8675,145.3500",
    "name": "Sherbrooke Falls",
    "rating": "4.2",
    "isDogFriendly": True,
    "maplink": "https://maps.apple.com/?address=Sherbrooke%20VIC%203789,%20Australia&auid=18397426523460711879&ll=-37.883790,145.357290&lsp=9902&q=Sherbrooke%20Falls%20Trail",
    "desc": "Sherbrooke Falls in Dandenong Ranges, VIC, is an easy trail leading to the beautiful Sherbrooke Falls, nestled in a lush forest setting.",
    "imagepreview": "https://www.parks.vic.gov.au/-/media/project/pv/main/parks/images/places-to-see/dandenong-ranges-national-park/dandenong-ranges-south/waterfalls-sherbrook-falls-dandenong-ranges-national-park-1920x1124.jpg?rev=2943c72e3f924987a71a5dfabf43a8f6",
    "imagecontextpreviews": [
      "https://www.parks.vic.gov.au/-/media/project/pv/main/parks/images/places-to-see/dandenong-ranges-national-park/dandenong-ranges-south/waterfalls-sherbrook-falls-dandenong-ranges-national-park-1920x1124.jpg?rev=2943c72e3f924987a71a5dfabf43a8f6",
      "https://images.squarespace-cdn.com/content/v1/6338330a337f6700f6f28fc9/1683263424299-FY6EPII1WXRF1NDJ8KX9/waterfall-1.jpg",
      "https://live.staticflickr.com/5241/5327110228_44eb17e556_b.jpg"
    ],
    "route": [
      {
        "latitude": -37.8675,
        "longitude": 145.3500
      },
      {
        "latitude": -37.8680,
        "longitude": 145.3510
      },
      {
        "latitude": -37.8690,
        "longitude": 145.3525
      },
      {
        "latitude": -37.8685,
        "longitude": 145.3515
      },
      {
        "latitude": -37.8675,
        "longitude": 145.3500
      }
    ]
  }
    ]
    return jsonify(suggested_hikes)


@app.route('/all_hikes', methods=['GET'])
@token_required  # Ensures this endpoint is protected as well
def get_all_hikes():
    # You can return some dummy hike data or integrate with your actual database
    hikes = [
  {
    "difficulty": "moderate",
    "distance": "8.4",
    "id": "9f1d835d-dc77-44a5-9234-5ef0a7a6a9d5",
    "location": "Blue Mountains, NSW",
    "weatherlocation": "-33.7365,150.3107",
    "name": "National Pass",
    "rating": "4.7",
    "maplink": "https://maps.apple.com/?address=Blue%20Mountains%20National%20Park%20NSW%202787,%20Australia&auid=8899488025313741809&ll=-33.725419,150.368811&lsp=9902&q=National%20Pass",
    "desc": "The National Pass in Blue Mountains, NSW, is a moderately difficult trail featuring stunning cliffside views and historic staircases carved into the rock.",
    "imagepreview": "https://www.nationalparks.nsw.gov.au/-/media/npws/images/parks/blue-mountains-national-park/katoomba-area/national-pass/national-pass-walk-06.jpg",
    "isDogFriendly": True,
    "imagecontextpreviews": [
      "https://www.nationalparks.nsw.gov.au/-/media/npws/images/parks/blue-mountains-national-park/katoomba-area/national-pass/national-pass-walk-06.jpg",
      "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.truebluemountains.com.au%2Fnational-pass-wentworth-falls%2F&psig=AOvVaw1ShysTwNR4os1zKDLLGHnW&ust=1725032159150000&source=images&cd=vfe&opi=89978449&ved=0CBQQjRxqFwoTCIjpmtrDmogDFQAAAAAdAAAAABAE",
      "https://dynamic-media-cdn.tripadvisor.com/media/photo-o/06/7a/53/0f/the-view-from-valley.jpg?w=1200&h=-1&s=1",
      "https://i0.wp.com/seektoseamore.com/wp-content/uploads/2018/06/P1010999.jpg?resize=775%2C581&ssl=1",
      "https://bushwalkingnsw.com/walk/985/20140906104310_650d_03521.jpg"
    ],
    "route": [
      {
        "latitude": -33.7365,
        "longitude": 150.3107
      },
      {
        "latitude": -33.7350,
        "longitude": 150.3090
      },
      {
        "latitude": -33.7335,
        "longitude": 150.3075
      },
      {
        "latitude": -33.7320,
        "longitude": 150.3060
      },
      {
        "latitude": -33.7310,
        "longitude": 150.3045
      },
      {
        "latitude": -33.7325,
        "longitude": 150.3030
      },
      {
        "latitude": -33.7340,
        "longitude": 150.3015
      },
      {
        "latitude": -33.7355,
        "longitude": 150.3000
      },
      {
        "latitude": -33.7370,
        "longitude": 150.3015
      },
      {
        "latitude": -33.7385,
        "longitude": 150.3030
      },
      {
        "latitude": -33.7370,
        "longitude": 150.3045
      },
      {
        "latitude": -33.7355,
        "longitude": 150.3060
      },
      {
        "latitude": -33.7340,
        "longitude": 150.3075
      },
      {
        "latitude": -33.7335,
        "longitude": 150.3090
      },
      {
        "latitude": -33.7350,
        "longitude": 150.3105
      },
      {
        "latitude": -33.7365,
        "longitude": 150.3107
      }
    ]
  },
  {
    "difficulty": "easy",
    "distance": "6.0",
    "id": "8c2dfb5f-8a3d-4f75-bc2b-02918b5d4328",
    "location": "Mornington Peninsula, VIC",
    "weatherlocation": "-38.4928,144.8641",
    "name": "Cape Schanck Lighthouse Walk",
    "rating": "4.6",
    "maplink": "https://maps.apple.com/?address=Mornington%20Peninsula%20National%20Park,%20Cape%20Schanck%20VIC%203939,%20Australia&ll=-38.495306,144.888361&q=Mornington%20Peninsula%20National%20Park",
    "desc": "Cape Schanck Lighthouse Walk in Mornington Peninsula, VIC, is an easy trail that takes you to the iconic lighthouse, offering breathtaking coastal views.",
    "imagepreview": "https://www.parks.vic.gov.au/-/media/project/pv/main/parks/images/places-to-see/mornington-peninsula-national-park/lighthouse-2-cape-schank-mornington-peninsula-national-park-1920x1124.jpg?rev=320a57ed43e345189315515a43764561",
    "isDogFriendly": False,
    "imagecontextpreviews": [
      "https://www.parks.vic.gov.au/-/media/project/pv/main/parks/images/places-to-see/mornington-peninsula-national-park/lighthouse-2-cape-schank-mornington-peninsula-national-park-1920x1124.jpg?rev=320a57ed43e345189315515a43764561",
      "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwalkingmaps.com.au%2Fwalk%2F4009&psig=AOvVaw0cpHB75c55znoPFNuzJJq6&ust=1725032544353000&source=images&cd=vfe&opi=89978449&ved=0CBQQjRxqFwoTCMiXlpLFmogDFQAAAAAdAAAAABAJ",
      "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.travelsewhere.net%2Fwalking-cape-schanck-victoria%2F&psig=AOvVaw0cpHB75c55znoPFNuzJJq6&ust=1725032544353000&source=images&cd=vfe&opi=89978449&ved=0CBQQjRxqFwoTCMiXlpLFmogDFQAAAAAdAAAAABAR",
      "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.visitmorningtonpeninsula.org%2Fplaces-to-see%2Ftowns-villages%2Fcape-schanck&psig=AOvVaw0cpHB75c55znoPFNuzJJq6&ust=1725032544353000&source=images&cd=vfe&opi=89978449&ved=0CBQQjRxqFwoTCMiXlpLFmogDFQAAAAAdAAAAABAZ",
      "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.racv.com.au%2Froyalauto%2Ftravel%2Fvictoria%2Fbest-walks-near-racv-resorts.html&psig=AOvVaw0cpHB75c55znoPFNuzJJq6&ust=1725032544353000&source=images&cd=vfe&opi=89978449&ved=0CBQQjRxqFwoTCMiXlpLFmogDFQAAAAAdAAAAABAh"
    ],
    "route": [
      {
        "latitude": -38.4928,
        "longitude": 144.8641
      },
      {
        "latitude": -38.4950,
        "longitude": 144.8660
      },
      {
        "latitude": -38.4972,
        "longitude": 144.8680
      },
      {
        "latitude": -38.4967,
        "longitude": 144.8699
      },
      {
        "latitude": -38.4945,
        "longitude": 144.8685
      },
      {
        "latitude": -38.4928,
        "longitude": 144.8670
      },
      {
        "latitude": -38.4928,
        "longitude": 144.8641
      }
    ]
  },
  {
    "difficulty": "hard",
    "distance": "10.2",
    "id": "fc6d2b7c-469a-4a5a-81d7-11d9ec817b78",
    "location": "Grampians, VIC",
    "weatherlocation": "-37.1497,142.5205",
    "name": "The Pinnacle Walk",
    "rating": "4.9",
    "maplink": "https://maps.apple.com/?address=Halls%20Gap%20VIC%203381,%20Australia&auid=1734491250711842809&ll=-37.150594,142.503018&lsp=9902&q=The%20Pinnacle%20walks",
    "desc": "The Pinnacle Walk in Grampians, VIC, is a challenging trail that rewards hikers with panoramic views from the top of the Pinnacle.",
    "imagepreview": "https://www.visitvictoria.com/-/media/images/grampians/things-to-do/nature-and-wildlife/the-pinnacle/the-pinnacle_gra-u_918098_1150x863.jpg?ts=20240503020151",
    "isDogFriendly": False,
    "imagecontextpreviews": [
      "https://www.visitvictoria.com/-/media/images/grampians/things-to-do/nature-and-wildlife/the-pinnacle/the-pinnacle_gra-u_918098_1150x863.jpg?ts=20240503020151"
    ],
    "route": [
      {
        "latitude": -37.1497,
        "longitude": 142.5205
      },
      {
        "latitude": -37.1475,
        "longitude": 142.5220
      },
      {
        "latitude": -37.1458,
        "longitude": 142.5233
      },
      {
        "latitude": -37.1440,
        "longitude": 142.5225
      },
      {
        "latitude": -37.1450,
        "longitude": 142.5205
      },
      {
        "latitude": -37.1497,
        "longitude": 142.5205
      }
    ]
  },
  {
    "difficulty": "moderate",
    "distance": "7.5",
    "id": "b7dcd4f3-9b41-4f84-bdef-1c4d5a9c94b2",
    "location": "Cradle Mountain, TAS",
    "weatherlocation": "-41.6467,145.9374",
    "name": "Dove Lake Circuit",
    "rating": "4.8",
    "maplink": "https://maps.apple.com/?address=Dove%20Lake%20Circuit,%20Cradle%20Mountain%20TAS%207306,%20Australia&auid=2703482302698274460&ll=-41.661334,145.959033&lsp=9902&q=Dove%20Lake%20Circuit",
    "desc": "Dove Lake Circuit in Cradle Mountain, TAS, is a moderate trail circling Dove Lake, providing picturesque views of Cradle Mountain and lush landscapes.",
    "isDogFriendly": True,
    "imagepreview": "https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhnHqDNJ_GBmVWigbzer6DR0qwcnyFcr2foVK9BgrrtDXI5XJlxjyCGCfkh8b1TvXWOJXlXUrSrxcUmIzj1wTy3F32mIID3L_krJb65qxGkftaotC0s0hZq9g4gmgQUYF-Fn4GgUl3ZG70/s1600/DSC06553.JPG",
    "imagecontextpreviews": [
      "https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhnHqDNJ_GBmVWigbzer6DR0qwcnyFcr2foVK9BgrrtDXI5XJlxjyCGCfkh8b1TvXWOJXlXUrSrxcUmIzj1wTy3F32mIID3L_krJb65qxGkftaotC0s0hZq9g4gmgQUYF-Fn4GgUl3ZG70/s1600/DSC06553.JPG"
    ],
    "route": [
      {
        "latitude": -41.6467,
        "longitude": 145.9374
      },
      {
        "latitude": -41.6480,
        "longitude": 145.9380
      },
      {
        "latitude": -41.6500,
        "longitude": 145.9400
      },
      {
        "latitude": -41.6520,
        "longitude": 145.9390
      },
      {
        "latitude": -41.6510,
        "longitude": 145.9370
      },
      {
        "latitude": -41.6467,
        "longitude": 145.9374
      }
    ]
  },
  {
    "difficulty": "easy",
    "distance": "4.5",
    "id": "efa6bc48-eae8-4533-b3e0-6e592c2fa6ab",
    "location": "Dandenong Ranges, VIC",
    "weatherlocation": "-37.8675,145.3500",
    "name": "Sherbrooke Falls",
    "rating": "4.2",
    "isDogFriendly": True,
    "maplink": "https://maps.apple.com/?address=Sherbrooke%20VIC%203789,%20Australia&auid=18397426523460711879&ll=-37.883790,145.357290&lsp=9902&q=Sherbrooke%20Falls%20Trail",
    "desc": "Sherbrooke Falls in Dandenong Ranges, VIC, is an easy trail leading to the beautiful Sherbrooke Falls, nestled in a lush forest setting.",
    "imagepreview": "https://www.parks.vic.gov.au/-/media/project/pv/main/parks/images/places-to-see/dandenong-ranges-national-park/dandenong-ranges-south/waterfalls-sherbrook-falls-dandenong-ranges-national-park-1920x1124.jpg?rev=2943c72e3f924987a71a5dfabf43a8f6",
    "imagecontextpreviews": [
      "https://www.parks.vic.gov.au/-/media/project/pv/main/parks/images/places-to-see/dandenong-ranges-national-park/dandenong-ranges-south/waterfalls-sherbrook-falls-dandenong-ranges-national-park-1920x1124.jpg?rev=2943c72e3f924987a71a5dfabf43a8f6",
      "https://images.squarespace-cdn.com/content/v1/6338330a337f6700f6f28fc9/1683263424299-FY6EPII1WXRF1NDJ8KX9/waterfall-1.jpg",
      "https://live.staticflickr.com/5241/5327110228_44eb17e556_b.jpg"
    ],
    "route": [
      {
        "latitude": -37.8675,
        "longitude": 145.3500
      },
      {
        "latitude": -37.8680,
        "longitude": 145.3510
      },
      {
        "latitude": -37.8690,
        "longitude": 145.3525
      },
      {
        "latitude": -37.8685,
        "longitude": 145.3515
      },
      {
        "latitude": -37.8675,
        "longitude": 145.3500
      }
    ]
  },
  {
    "difficulty": "moderate",
    "distance": "5.7",
    "id": "0eb5bd7d-ebda-43c8-8d2c-7f351387708a",
    "location": "Yarra Ranges, VIC",
    "weatherlocation": "-37.3300,145.7500",
    "name": "Cathedral Range Southern Circuit",
    "rating": "4.6",
    "isDogFriendly": False,
    "maplink": "https://maps.apple.com/?address=Cathedral%20Range%20State%20Park,%20Tweed%20Spur%20Rd,%20Taggerty%20VIC%203712,%20Australia&ll=-37.381549,145.761934&q=Cathedral%20Range%20State%20Park",
    "desc": "Cathedral Range Southern Circuit in Yarra Ranges, VIC, is a moderate trail offering a mix of rugged terrain and spectacular views of the Cathedral Range.",
    "imagepreview": "https://www.paddypallin.com.au/blog/wp-content/uploads/2020/06/Cathedral-Ranges-Sourthern-Circuit.-Photograph-.jpg",
    "imagecontextpreviews": [
      "https://www.paddypallin.com.au/blog/wp-content/uploads/2020/06/Cathedral-Ranges-Sourthern-Circuit.-Photograph-.jpg"
    ],
    "route": [
      {
        "latitude": -37.3300,
        "longitude": 145.7500
      },
      {
        "latitude": -37.3310,
        "longitude": 145.7520
      },
      {
        "latitude": -37.3320,
        "longitude": 145.7540
      },
      {
        "latitude": -37.3330,
        "longitude": 145.7560
      },
      {
        "latitude": -37.3340,
        "longitude": 145.7580
      },
      {
        "latitude": -37.3350,
        "longitude": 145.7600
      },
      {
        "latitude": -37.3360,
        "longitude": 145.7620
      },
      {
        "latitude": -37.3370,
        "longitude": 145.7640
      },
      {
        "latitude": -37.3380,
        "longitude": 145.7660
      },
      {
        "latitude": -37.3390,
        "longitude": 145.7680
      },
      {
        "latitude": -37.3400,
        "longitude": 145.7700
      },
      {
        "latitude": -37.3410,
        "longitude": 145.7720
      },
      {
        "latitude": -37.3420,
        "longitude": 145.7740
      },
      {
        "latitude": -37.3430,
        "longitude": 145.7760
      },
      {
        "latitude": -37.3440,
        "longitude": 145.7780
      },
      {
        "latitude": -37.3450,
        "longitude": 145.7800
      },
      {
        "latitude": -37.3460,
        "longitude": 145.7820
      },
      {
        "latitude": -37.3470,
        "longitude": 145.7840
      },
      {
        "latitude": -37.3480,
        "longitude": 145.7860
      },
      {
        "latitude": -37.3490,
        "longitude": 145.7880
      },
      {
        "latitude": -37.3500,
        "longitude": 145.7900
      },
      {
        "latitude": -37.3510,
        "longitude": 145.7920
      },
      {
        "latitude": -37.3520,
        "longitude": 145.7940
      },
      {
        "latitude": -37.3530,
        "longitude": 145.7960
      },
      {
        "latitude": -37.3540,
        "longitude": 145.7980
      },
      {
        "latitude": -37.3550,
        "longitude": 145.8000
      },
      {
        "latitude": -37.3560,
        "longitude": 145.8020
      },
      {
        "latitude": -37.3570,
        "longitude": 145.8040
      },
      {
        "latitude": -37.3580,
        "longitude": 145.8060
      },
      {
        "latitude": -37.3590,
        "longitude": 145.8080
      },
      {
        "latitude": -37.3600,
        "longitude": 145.8100
      },
      {
        "latitude": -37.3610,
        "longitude": 145.8120
      },
      {
        "latitude": -37.3620,
        "longitude": 145.8140
      },
      {
        "latitude": -37.3630,
        "longitude": 145.8160
      },
      {
        "latitude": -37.3640,
        "longitude": 145.8180
      },
      {
        "latitude": -37.3650,
        "longitude": 145.8200
      },
      {
        "latitude": -37.3660,
        "longitude": 145.8220
      },
      {
        "latitude": -37.3670,
        "longitude": 145.8240
      },
      {
        "latitude": -37.3680,
        "longitude": 145.8260
      },
      {
        "latitude": -37.3690,
        "longitude": 145.8280
      },
      {
        "latitude": -37.3700,
        "longitude": 145.8300
      },
      {
        "latitude": -37.3710,
        "longitude": 145.8320
      },
      {
        "latitude": -37.3720,
        "longitude": 145.8340
      },
      {
        "latitude": -37.3730,
        "longitude": 145.8360
      },
      {
        "latitude": -37.3740,
        "longitude": 145.8380
      },
      {
        "latitude": -37.3750,
        "longitude": 145.8400
      },
      {
        "latitude": -37.3760,
        "longitude": 145.8420
      },
      {
        "latitude": -37.3770,
        "longitude": 145.8440
      },
      {
        "latitude": -37.3780,
        "longitude": 145.8460
      },
      {
        "latitude": -37.3790,
        "longitude": 145.8480
      },
      {
        "latitude": -37.3800,
        "longitude": 145.8500
      },
      {
        "latitude": -37.3810,
        "longitude": 145.8520
      },
      {
        "latitude": -37.3820,
        "longitude": 145.8540
      },
      {
        "latitude": -37.3830,
        "longitude": 145.8560
      },
      {
        "latitude": -37.3840,
        "longitude": 145.8580
      },
      {
        "latitude": -37.3850,
        "longitude": 145.8600
      },
      {
        "latitude": -37.3860,
        "longitude": 145.8620
      },
      {
        "latitude": -37.3870,
        "longitude": 145.8640
      },
      {
        "latitude": -37.3880,
        "longitude": 145.8660
      },
      {
        "latitude": -37.3890,
        "longitude": 145.8680
      },
      {
        "latitude": -37.3900,
        "longitude": 145.8700
      },
      {
        "latitude": -37.3910,
        "longitude": 145.8720
      },
      {
        "latitude": -37.3920,
        "longitude": 145.8740
      },
      {
        "latitude": -37.3930,
        "longitude": 145.8760
      },
      {
        "latitude": -37.3940,
        "longitude": 145.8780
      },
      {
        "latitude": -37.3950,
        "longitude": 145.8800
      },
      {
        "latitude": -37.3960,
        "longitude": 145.8820
      },
      {
        "latitude": -37.3970,
        "longitude": 145.8840
      },
      {
        "latitude": -37.3980,
        "longitude": 145.8860
      },
      {
        "latitude": -37.3990,
        "longitude": 145.8880
      },
      {
        "latitude": -37.4000,
        "longitude": 145.8900
      },
      {
        "latitude": -37.4010,
        "longitude": 145.8920
      },
      {
        "latitude": -37.4020,
        "longitude": 145.8940
      },
      {
        "latitude": -37.4030,
        "longitude": 145.8960
      },
      {
        "latitude": -37.4040,
        "longitude": 145.8980
      },
      {
        "latitude": -37.4050,
        "longitude": 145.9000
      },
      {
        "latitude": -37.4060,
        "longitude": 145.9020
      },
      {
        "latitude": -37.4070,
        "longitude": 145.9040
      },
      {
        "latitude": -37.4080,
        "longitude": 145.9060
      },
      {
        "latitude": -37.4090,
        "longitude": 145.9080
      },
      {
        "latitude": -37.4100,
        "longitude": 145.9100
      },
      {
        "latitude": -37.4110,
        "longitude": 145.9120
      },
      {
        "latitude": -37.4120,
        "longitude": 145.9140
      },
      {
        "latitude": -37.4130,
        "longitude": 145.9160
      },
      {
        "latitude": -37.4140,
        "longitude": 145.9180
      },
      {
        "latitude": -37.4150,
        "longitude": 145.9200
      },
      {
        "latitude": -37.4160,
        "longitude": 145.9220
      },
            {
        "latitude": -37.4170,
        "longitude": 145.9240
      },
      {
        "latitude": -37.4180,
        "longitude": 145.9260
      },
      {
        "latitude": -37.4190,
        "longitude": 145.9280
      },
      {
        "latitude": -37.4200,
        "longitude": 145.9300
      },
      {
        "latitude": -37.4210,
        "longitude": 145.9320
      },
      {
        "latitude": -37.4220,
        "longitude": 145.9340
      },
      {
        "latitude": -37.4230,
        "longitude": 145.9360
      },
      {
        "latitude": -37.4240,
        "longitude": 145.9380
      },
      {
        "latitude": -37.4250,
        "longitude": 145.9400
      },
      {
        "latitude": -37.4260,
        "longitude": 145.9420
      },
      {
        "latitude": -37.4270,
        "longitude": 145.9440
      },
      {
        "latitude": -37.4280,
        "longitude": 145.9460
      },
      {
        "latitude": -37.4290,
        "longitude": 145.9480
      },
      {
        "latitude": -37.4300,
        "longitude": 145.9500
      },
      {
        "latitude": -37.4310,
        "longitude": 145.9520
      },
      {
        "latitude": -37.4320,
        "longitude": 145.9540
      },
      {
        "latitude": -37.4330,
        "longitude": 145.9560
      },
      {
        "latitude": -37.4340,
        "longitude": 145.9580
      },
      {
        "latitude": -37.4350,
        "longitude": 145.9600
      },
      {
        "latitude": -37.4360,
        "longitude": 145.9620
      },
      {
        "latitude": -37.4370,
        "longitude": 145.9640
      },
      {
        "latitude": -37.4380,
        "longitude": 145.9660
      },
      {
        "latitude": -37.4390,
        "longitude": 145.9680
      },
      {
        "latitude": -37.4400,
        "longitude": 145.9700
      },
      {
        "latitude": -37.4410,
        "longitude": 145.9720
      },
      {
        "latitude": -37.4420,
        "longitude": 145.9740
      },
      {
        "latitude": -37.4430,
        "longitude": 145.9760
      },
      {
        "latitude": -37.4440,
        "longitude": 145.9780
      },
      {
        "latitude": -37.4450,
        "longitude": 145.9800
      },
      {
        "latitude": -37.4460,
        "longitude": 145.9820
      },
      {
        "latitude": -37.4470,
        "longitude": 145.9840
      },
      {
        "latitude": -37.4480,
        "longitude": 145.9860
      },
      {
        "latitude": -37.4490,
        "longitude": 145.9880
      },
      {
        "latitude": -37.4500,
        "longitude": 145.9900
      },
      {
        "latitude": -37.4510,
        "longitude": 145.9920
      },
      {
        "latitude": -37.4520,
        "longitude": 145.9940
      },
      {
        "latitude": -37.4530,
        "longitude": 145.9960
      },
      {
        "latitude": -37.4540,
        "longitude": 145.9980
      },
      {
        "latitude": -37.4550,
        "longitude": 146.0000
      },
      {
        "latitude": -37.4560,
        "longitude": 146.0020
      },
      {
        "latitude": -37.4570,
        "longitude": 146.0040
      },
      {
        "latitude": -37.4580,
        "longitude": 146.0060
      },
      {
        "latitude": -37.4590,
        "longitude": 146.0080
      },
      {
        "latitude": -37.4600,
        "longitude": 146.0100
      },
      {
        "latitude": -37.4610,
        "longitude": 146.0120
      },
      {
        "latitude": -37.4620,
        "longitude": 146.0140
      },
      {
        "latitude": -37.4630,
        "longitude": 146.0160
      },
      {
        "latitude": -37.4640,
        "longitude": 146.0180
      },
      {
        "latitude": -37.4650,
        "longitude": 146.0200
      },
      {
        "latitude": -37.4660,
        "longitude": 146.0220
      },
      {
        "latitude": -37.4670,
        "longitude": 146.0240
      },
      {
        "latitude": -37.4680,
        "longitude": 146.0260
      },
      {
        "latitude": -37.4690,
        "longitude": 146.0280
      },
      {
        "latitude": -37.4700,
        "longitude": 146.0300
      },
      {
        "latitude": -37.4710,
        "longitude": 146.0320
      },
      {
        "latitude": -37.4720,
        "longitude": 146.0340
      },
      {
        "latitude": -37.4730,
        "longitude": 146.0360
      },
      {
        "latitude": -37.4740,
        "longitude": 146.0380
      },
      {
        "latitude": -37.4750,
        "longitude": 146.0400
      },
      {
        "latitude": -37.4760,
        "longitude": 146.0420
      },
      {
        "latitude": -37.4770,
        "longitude": 146.0440
      },
      {
        "latitude": -37.4780,
        "longitude": 146.0460
      },
      {
        "latitude": -37.4790,
        "longitude": 146.0480
      },
      {
        "latitude": -37.4800,
        "longitude": 146.0500
      },
      {
        "latitude": -37.4810,
        "longitude": 146.0520
      },
      {
        "latitude": -37.4820,
        "longitude": 146.0540
      },
      {
        "latitude": -37.4830,
        "longitude": 146.0560
      },
      {
        "latitude": -37.4840,
        "longitude": 146.0580
      },
      {
        "latitude": -37.4850,
        "longitude": 146.0600
      },
      {
        "latitude": -37.4860,
        "longitude": 146.0620
      },
      {
        "latitude": -37.4870,
        "longitude": 146.0640
      },
      {
        "latitude": -37.4880,
        "longitude": 146.0660
      },
      {
        "latitude": -37.4890,
        "longitude": 146.0680
      },
      {
        "latitude": -37.4900,
        "longitude": 146.0700
      },
      {
        "latitude": -37.4910,
        "longitude": 146.0720
      },
      {
        "latitude": -37.4920,
        "longitude": 146.0740
      },
      {
        "latitude": -37.4930,
        "longitude": 146.0760
      },
      {
        "latitude": -37.4940,
        "longitude": 146.0780
      },
      {
        "latitude": -37.4950,
        "longitude": 146.0800
      },
      {
        "latitude": -37.4960,
        "longitude": 146.0820
      },
      {
        "latitude": -37.4970,
        "longitude": 146.0840
      },
      {
        "latitude": -37.4980,
        "longitude": 146.0860
      },
      {
        "latitude": -37.4990,
        "longitude": 146.0880
      },
      {
        "latitude": -37.5000,
        "longitude": 146.0900
      }
    ]
  },
  {
    "difficulty": "easy",
    "distance": "3.4",
    "id": "bfcecf17-b405-449b-8a02-eea338733b2a",
    "location": "Royal National Park, NSW",
    "weatherlocation": "-34.1368,151.0204",
    "name": "Figure Eight Pools",
    "rating": "4.5",
    "maplink": "https://maps.apple.com/?address=Lilyvale%20NSW%202508%0AAustralia&auid=9251853819996220033&ll=-34.180252,151.039332&lsp=9902&q=Garawarra%20Farm%20Carpark%20to%20Figure%20Eight%20Pools",
    "desc": "Figure Eight Pools in Royal National Park, NSW, is an easy trail that leads to unique rock formations and naturally formed pools shaped like figure eights.",
    "imagepreview": "https://i0.wp.com/hikingtheworld.blog/wp-content/uploads/2017/12/mg_8243-lr.jpg",
    "isDogFriendly": True,
    "imagecontextpreviews": [
      "https://i0.wp.com/hikingtheworld.blog/wp-content/uploads/2017/12/mg_8243-lr.jpg"
    ],
    "route": [
      {
        "latitude": -34.1368,
        "longitude": 151.0204
      },
      {
        "latitude": -34.1370,
        "longitude": 151.0210
      },
      {
        "latitude": -34.1372,
        "longitude": 151.0215
      },
      {
        "latitude": -34.1375,
        "longitude": 151.0220
      },
      {
        "latitude": -34.1380,
        "longitude": 151.0225
      },
      {
        "latitude": -34.1382,
        "longitude": 151.0230
      },
      {
        "latitude": -34.1385,
        "longitude": 151.0235
      },
      {
        "latitude": -34.1390,
        "longitude": 151.0240
      },
      {
        "latitude": -34.1392,
        "longitude": 151.0245
      },
      {
        "latitude": -34.1395,
        "longitude": 151.0250
      },
      {
        "latitude": -34.1397,
        "longitude": 151.0255
      },
      {
        "latitude": -34.1400,
        "longitude": 151.0260
      },
      {
        "latitude": -34.1402,
        "longitude": 151.0265
      },
      {
        "latitude": -34.1405,
        "longitude": 151.0270
      },
      {
        "latitude": -34.1407,
        "longitude": 151.0275
      },
      {
        "latitude": -34.1410,
        "longitude": 151.0280
      },
      {
        "latitude": -34.1412,
        "longitude": 151.0285
      },
      {
        "latitude": -34.1415,
        "longitude": 151.0290
      },
      {
        "latitude": -34.1417,
        "longitude": 151.0295
      },
      {
        "latitude": -34.1420,
        "longitude": 151.0300
      },
      {
        "latitude": -34.1422,
        "longitude": 151.0305
      },
      {
        "latitude": -34.1425,
        "longitude": 151.0310
      },
      {
        "latitude": -34.1427,
        "longitude": 151.0315
      },
      {
        "latitude": -34.1430,
        "longitude": 151.0320
      },
      {
        "latitude": -34.1432,
        "longitude": 151.0325
      },
      {
        "latitude": -34.1435,
        "longitude": 151.0330
      },
      {
        "latitude": -34.1437,
        "longitude": 151.0335
      },
      {
        "latitude": -34.1440,
        "longitude": 151.0340
      },
      {
        "latitude": -34.1442,
        "longitude": 151.0345
      },
      {
        "latitude": -34.1445,
        "longitude": 151.0350
      },
      {
        "latitude": -34.1447,
        "longitude": 151.0355
      },
      {
        "latitude": -34.1450,
        "longitude": 151.0360
      },
      {
        "latitude": -34.1452,
        "longitude": 151.0365
      },
      {
        "latitude": -34.1455,
        "longitude": 151.0370
      },
      {
        "latitude": -34.1457,
        "longitude": 151.0375
      },
      {
        "latitude": -34.1460,
        "longitude": 151.0380
      },
      {
        "latitude": -34.1462,
        "longitude": 151.0385
      },
      {
        "latitude": -34.1465,
        "longitude": 151.0390
      },
      {
        "latitude": -34.1467,
        "longitude": 151.0395
      },
      {
        "latitude": -34.1470,
        "longitude": 151.0400
      },
      {
        "latitude": -34.1472,
        "longitude": 151.0405
      },
      {
        "latitude": -34.1475,
        "longitude": 151.0410
      },
      {
        "latitude": -34.1477,
        "longitude": 151.0415
      },
      {
        "latitude": -34.1480,
        "longitude": 151.0420
      },
      {
        "latitude": -34.1482,
        "longitude": 151.0425
      },
      {
        "latitude": -34.1485,
        "longitude": 151.0430
      },
      {
        "latitude": -34.1487,
        "longitude": 151.0435
      },
      {
        "latitude": -34.1490,
        "longitude": 151.0440
      },
      {
        "latitude": -34.1492,
        "longitude": 151.0445
      },
      {
        "latitude": -34.1495,
        "longitude": 151.0450
      },
      {
        "latitude": -34.1497,
        "longitude": 151.0455
      },
      {
        "latitude": -34.1500,
        "longitude": 151.0460
      }
    ]
  },
  {
    "difficulty": "hard",
    "distance": "12.1",
    "id": "2fcd61a9-14f4-4e89-8c68-5d7a92f76a0b",
    "location": "Kosciuszko National Park, NSW",
    "weatherlocation": "-36.4310,148.3000",
    "name": "Main Range Walk",
    "isDogFriendly": False,
    "rating": "4.9",
    "maplink": "https://maps.apple.com/?address=Charlotte%20Pass%20NSW%202624,%20Australia&auid=5541615254328519961&ll=-36.431640,148.328591&lsp=9902&q=Main%20Range%20walk",
    "desc": "Main Range Walk in Kosciuszko National Park, NSW, is a hard trail offering a challenging hike with stunning alpine scenery and glacial lakes.",
    "imagepreview": "https://www.nationalparks.nsw.gov.au/-/media/npws/images/parks/kosciuszko-national-park/thredbo-perisher-area/main-range-walk/main-range-walk-blue-lake04.jpg",
    "imagecontextpreviews": [
      "https://www.nationalparks.nsw.gov.au/-/media/npws/images/parks/kosciuszko-national-park/thredbo-perisher-area/main-range-walk/main-range-walk-blue-lake04.jpg"
    ],
    "route": [
      {
        "latitude": -36.4310,
        "longitude": 148.3000
      },
      {
        "latitude": -36.4320,
        "longitude": 148.3050
      },
      {
        "latitude": -36.4330,
        "longitude": 148.3100
      },
      {
        "latitude": -36.4340,
        "longitude": 148.3150
      },
      {
        "latitude": -36.4350,
        "longitude": 148.3200
      },
      {
        "latitude": -36.4360,
        "longitude": 148.3250
      },
      {
        "latitude": -36.4370,
        "longitude": 148.3300
      },
      {
        "latitude": -36.4380,
        "longitude": 148.3350
      },
      {
        "latitude": -36.4390,
        "longitude": 148.3400
      },
      {
        "latitude": -36.4400,
        "longitude": 148.3450
      },
      {
        "latitude": -36.4410,
        "longitude": 148.3500
      },
      {
        "latitude": -36.4420,
        "longitude": 148.3550
      },
      {
        "latitude": -36.4430,
        "longitude": 148.3600
      },
      {
        "latitude": -36.4440,
        "longitude": 148.3650
      },
      {
        "latitude": -36.4450,
        "longitude": 148.3700
      },
      {
        "latitude": -36.4460,
        "longitude": 148.3750
      },
      {
        "latitude": -36.4470,
        "longitude": 148.3800
      },
      {
        "latitude": -36.4480,
        "longitude": 148.3850
      },
      {
        "latitude": -36.4490,
        "longitude": 148.3900
      },
      {
        "latitude": -36.4500,
        "longitude": 148.3950
      },
      {
        "latitude": -36.4510,
        "longitude": 148.4000
      },
      {
        "latitude": -36.4520,
        "longitude": 148.4050
      },
      {
        "latitude": -36.4530,
        "longitude": 148.4100
      },
      {
        "latitude": -36.4540,
        "longitude": 148.4150
      },
      {
        "latitude": -36.4550,
        "longitude": 148.4200
      },
      {
        "latitude": -36.4560,
        "longitude": 148.4250
      },
      {
        "latitude": -36.4570,
        "longitude": 148.4300
      },
      {
        "latitude": -36.4580,
        "longitude": 148.4350
      },
      {
        "latitude": -36.4590,
        "longitude": 148.4400
      },
      {
        "latitude": -36.4600,
        "longitude": 148.4450
      },
      {
        "latitude": -36.4610,
        "longitude": 148.4500
      },
      {
        "latitude": -36.4620,
        "longitude": 148.4550
      },
      {
        "latitude": -36.4630,
        "longitude": 148.4600
      },
      {
        "latitude": -36.4640,
        "longitude": 148.4650
      },
      {
        "latitude": -36.4650,
        "longitude": 148.4700
      },
      {
        "latitude": -36.4660,
        "longitude": 148.4750
      },
      {
        "latitude": -36.4670,
        "longitude": 148.4800
      },
      {
        "latitude": -36.4680,
        "longitude": 148.4850
      },
      {
        "latitude": -36.4690,
        "longitude": 148.4900
      },
      {
        "latitude": -36.4700,
        "longitude": 148.4950
      },
      {
        "latitude": -36.4710,
        "longitude": 148.5000
      },
      {
        "latitude": -36.4720,
        "longitude": 148.5050
      },
      {
        "latitude": -36.4730,
        "longitude": 148.5100
      },
      {
        "latitude": -36.4740,
        "longitude": 148.5150
      },
      {
        "latitude": -36.4750,
        "longitude": 148.5200
      },
      {
        "latitude": -36.4760,
        "longitude": 148.5250
      },
      {
        "latitude": -36.4770,
        "longitude": 148.5300
      },
      {
        "latitude": -36.4780,
        "longitude": 148.5350
      },
      {
        "latitude": -36.4790,
        "longitude": 148.5400
      },
      {
        "latitude": -36.4800,
        "longitude": 148.5450
      },
      {
        "latitude": -36.4810,
        "longitude": 148.5500
      },
      {
        "latitude": -36.4820,
        "longitude": 148.5550
      },
      {
        "latitude": -36.4830,
        "longitude": 148.5600
      },
      {
        "latitude": -36.4840,
        "longitude": 148.5650
      },
      {
        "latitude": -36.4850,
        "longitude": 148.5700
      },
      {
        "latitude": -36.4860,
        "longitude": 148.5750
      },
      {
        "latitude": -36.4870,
        "longitude": 148.5800
      },
      {
        "latitude": -36.4880,
        "longitude": 148.5850
      },
      {
        "latitude": -36.4890,
        "longitude": 148.5900
      },
      {
        "latitude": -36.4900,
        "longitude": 148.5950
      },
      {
        "latitude": -36.4910,
        "longitude": 148.6000
      }
    ]
  },
  {
    "difficulty": "easy",
    "distance": "16",
    "id": "8831978c-7656-401b-a96c-508cea772a70",
    "location": "Joondalup, WA",
    "weatherlocation": "-31.7451,115.7642",
    "name": "Lake Joondalup Circuit",
    "rating": "4.1",
    "isDogFriendly": False,
    "maplink": "https://maps.apple.com/?address=Neerabup%20WA%206027,%20Australia&auid=1682933006947521939&ll=-31.718976,115.762517&lsp=9902&q=Yaberoo%20Budjara%20Heritage%20Trail",
    "desc": "Lake Joondalup Circuit in Joondalup, WA, is an easy trail that circles Lake Joondalup, providing serene views and opportunities for birdwatching.",
    "imagepreview": "https://trailswa.com.au/storage/media/9yz4pkrk5qdk/conversions/Joondalup-Circuit_YellagongaRP_MargaretGreville-crop-1066x840-webp.webp",
    "imagecontextpreviews": [
      "https://trailswa.com.au/storage/media/9yz4pkrk5qdk/conversions/Joondalup-Circuit_YellagongaRP_MargaretGreville-crop-1066x840-webp.webp"
    ],
    "route": [
      {
        "latitude": -31.7451,
        "longitude": 115.7642
      },
      {
        "latitude": -31.7460,
        "longitude": 115.7650
      },
      {
        "latitude": -31.7470,
        "longitude": 115.7660
      },
      {
        "latitude": -31.7480,
        "longitude": 115.7670
      },
      {
        "latitude": -31.7490,
        "longitude": 115.7680
      },
      {
        "latitude": -31.7500,
        "longitude": 115.7690
      },
            {
        "latitude": -31.7510,
        "longitude": 115.7700
      },
      {
        "latitude": -31.7520,
        "longitude": 115.7710
      },
      {
        "latitude": -31.7530,
        "longitude": 115.7720
      },
      {
        "latitude": -31.7540,
        "longitude": 115.7730
      },
      {
        "latitude": -31.7550,
        "longitude": 115.7740
      },
      {
        "latitude": -31.7560,
        "longitude": 115.7750
      },
      {
        "latitude": -31.7570,
        "longitude": 115.7760
      },
      {
        "latitude": -31.7580,
        "longitude": 115.7770
      },
      {
        "latitude": -31.7590,
        "longitude": 115.7780
      },
      {
        "latitude": -31.7600,
        "longitude": 115.7790
      },
      {
        "latitude": -31.7610,
        "longitude": 115.7800
      },
      {
        "latitude": -31.7620,
        "longitude": 115.7810
      },
      {
        "latitude": -31.7630,
        "longitude": 115.7820
      },
      {
        "latitude": -31.7640,
        "longitude": 115.7830
      },
      {
        "latitude": -31.7650,
        "longitude": 115.7840
      },
      {
        "latitude": -31.7660,
        "longitude": 115.7850
      },
      {
        "latitude": -31.7670,
        "longitude": 115.7860
      },
      {
        "latitude": -31.7680,
        "longitude": 115.7870
      },
      {
        "latitude": -31.7690,
        "longitude": 115.7880
      },
      {
        "latitude": -31.7700,
        "longitude": 115.7890
      },
      {
        "latitude": -31.7710,
        "longitude": 115.7900
      },
      {
        "latitude": -31.7720,
        "longitude": 115.7910
      },
      {
        "latitude": -31.7730,
        "longitude": 115.7920
      },
      {
        "latitude": -31.7740,
        "longitude": 115.7930
      },
      {
        "latitude": -31.7750,
        "longitude": 115.7940
      },
      {
        "latitude": -31.7760,
        "longitude": 115.7950
      },
      {
        "latitude": -31.7770,
        "longitude": 115.7960
      },
      {
        "latitude": -31.7780,
        "longitude": 115.7970
      },
      {
        "latitude": -31.7790,
        "longitude": 115.7980
      },
      {
        "latitude": -31.7800,
        "longitude": 115.7990
      },
      {
        "latitude": -31.7810,
        "longitude": 115.8000
      },
      {
        "latitude": -31.7820,
        "longitude": 115.8010
      },
      {
        "latitude": -31.7830,
        "longitude": 115.8020
      },
      {
        "latitude": -31.7840,
        "longitude": 115.8030
      },
      {
        "latitude": -31.7850,
        "longitude": 115.8040
      },
      {
        "latitude": -31.7860,
        "longitude": 115.8050
      },
      {
        "latitude": -31.7870,
        "longitude": 115.8060
      },
      {
        "latitude": -31.7880,
        "longitude": 115.8070
      },
      {
        "latitude": -31.7890,
        "longitude": 115.8080
      },
      {
        "latitude": -31.7900,
        "longitude": 115.8090
      },
      {
        "latitude": -31.7910,
        "longitude": 115.8100
      },
      {
        "latitude": -31.7920,
        "longitude": 115.8110
      },
      {
        "latitude": -31.7930,
        "longitude": 115.8120
      },
      {
        "latitude": -31.7940,
        "longitude": 115.8130
      },
      {
        "latitude": -31.7950,
        "longitude": 115.8140
      },
      {
        "latitude": -31.7960,
        "longitude": 115.8150
      },
      {
        "latitude": -31.7970,
        "longitude": 115.8160
      },
      {
        "latitude": -31.7980,
        "longitude": 115.8170
      },
      {
        "latitude": -31.7990,
        "longitude": 115.8180
      },
      {
        "latitude": -31.8000,
        "longitude": 115.8190
      },
      {
        "latitude": -31.8010,
        "longitude": 115.8200
      },
      {
        "latitude": -31.8020,
        "longitude": 115.8210
      },
      {
        "latitude": -31.8030,
        "longitude": 115.8220
      },
      {
        "latitude": -31.8040,
        "longitude": 115.8230
      },
      {
        "latitude": -31.8050,
        "longitude": 115.8240
      },
      {
        "latitude": -31.8060,
        "longitude": 115.8250
      },
      {
        "latitude": -31.8070,
        "longitude": 115.8260
      },
      {
        "latitude": -31.8080,
        "longitude": 115.8270
      },
      {
        "latitude": -31.8090,
        "longitude": 115.8280
      },
      {
        "latitude": -31.8100,
        "longitude": 115.8290
      },
      {
        "latitude": -31.8110,
        "longitude": 115.8300
      },
      {
        "latitude": -31.8120,
        "longitude": 115.8310
      },
      {
        "latitude": -31.8130,
        "longitude": 115.8320
      },
      {
        "latitude": -31.8140,
        "longitude": 115.8330
      },
      {
        "latitude": -31.8150,
        "longitude": 115.8340
      },
      {
        "latitude": -31.8160,
        "longitude": 115.8350
      },
      {
        "latitude": -31.8170,
        "longitude": 115.8360
      },
      {
        "latitude": -31.8180,
        "longitude": 115.8370
      },
      {
        "latitude": -31.8190,
        "longitude": 115.8380
      },
      {
        "latitude": -31.8200,
        "longitude": 115.8390
      },
      {
        "latitude": -31.8210,
        "longitude": 115.8400
      },
      {
        "latitude": -31.8220,
        "longitude": 115.8410
      },
      {
        "latitude": -31.8230,
        "longitude": 115.8420
      },
      {
        "latitude": -31.8240,
        "longitude": 115.8430
      },
      {
        "latitude": -31.8250,
        "longitude": 115.8440
      },
      {
        "latitude": -31.8260,
        "longitude": 115.8450
      },
      {
        "latitude": -31.8270,
        "longitude": 115.8460
      },
      {
        "latitude": -31.8280,
        "longitude": 115.8470
      },
      {
        "latitude": -31.8290,
        "longitude": 115.8480
      },
      {
        "latitude": -31.8300,
        "longitude": 115.8490
      },
      {
        "latitude": -31.8310,
        "longitude": 115.8500
      },
      {
        "latitude": -31.8320,
        "longitude": 115.8510
      },
      {
        "latitude": -31.8330,
        "longitude": 115.8520
      },
      {
        "latitude": -31.8340,
        "longitude": 115.8530
      },
      {
        "latitude": -31.8350,
        "longitude": 115.8540
      },
      {
        "latitude": -31.8360,
        "longitude": 115.8550
      },
      {
        "latitude": -31.8370,
        "longitude": 115.8560
      },
      {
        "latitude": -31.8380,
        "longitude": 115.8570
      },
      {
        "latitude": -31.8390,
        "longitude": 115.8580
      },
      {
        "latitude": -31.8400,
        "longitude": 115.8590
      },
      {
        "latitude": -31.8410,
        "longitude": 115.8600
      },
      {
        "latitude": -31.8420,
        "longitude": 115.8610
      },
      {
        "latitude": -31.8430,
        "longitude": 115.8620
      },
      {
        "latitude": -31.8440,
        "longitude": 115.8630
      },
      {
        "latitude": -31.8450,
        "longitude": 115.8640
      },
      {
        "latitude": -31.8460,
        "longitude": 115.8650
      },
      {
        "latitude": -31.8470,
        "longitude": 115.8660
      },
      {
        "latitude": -31.8480,
        "longitude": 115.8670
      },
      {
        "latitude": -31.8490,
        "longitude": 115.8680
      },
      {
        "latitude": -31.8500,
        "longitude": 115.8690
      },
      {
        "latitude": -31.8510,
        "longitude": 115.8700
      },
      {
        "latitude": -31.8520,
        "longitude": 115.8710
      },
      {
        "latitude": -31.8530,
        "longitude": 115.8720
      },
      {
        "latitude": -31.8540,
        "longitude": 115.8730
      },
      {
        "latitude": -31.8550,
        "longitude": 115.8740
      },
      {
        "latitude": -31.8560,
        "longitude": 115.8750
      },
      {
        "latitude": -31.8570,
        "longitude": 115.8760
      },
      {
        "latitude": -31.8580,
        "longitude": 115.8770
      },
      {
        "latitude": -31.8590,
        "longitude": 115.8780
      },
      {
        "latitude": -31.8600,
        "longitude": 115.8790
      },
      {
        "latitude": -31.8610,
        "longitude": 115.8800
      },
      {
        "latitude": -31.8620,
        "longitude": 115.8810
      },
      {
        "latitude": -31.8630,
        "longitude": 115.8820
      },
      {
        "latitude": -31.8640,
        "longitude": 115.8830
      },
      {
        "latitude": -31.8650,
        "longitude": 115.8840
      },
      {
        "latitude": -31.8660,
        "longitude": 115.8850
      },
      {
        "latitude": -31.8670,
        "longitude": 115.8860
      },
      {
        "latitude": -31.8680,
        "longitude": 115.8870
      },
      {
        "latitude": -31.8690,
        "longitude": 115.8880
      },
      {
        "latitude": -31.8700,
        "longitude": 115.8890
      },
      {
        "latitude": -31.8710,
        "longitude": 115.8900
      },
      {
        "latitude": -31.8720,
        "longitude": 115.8910
      },
      {
        "latitude": -31.8730,
        "longitude": 115.8920
      },
      {
        "latitude": -31.8740,
        "longitude": 115.8930
      },
      {
        "latitude": -31.8750,
        "longitude": 115.8940
      },
      {
        "latitude": -31.8760,
        "longitude": 115.8950
      },
      {
        "latitude": -31.8770,
        "longitude": 115.8960
      },
      {
        "latitude": -31.8780,
        "longitude": 115.8970
      },
      {
        "latitude": -31.8790,
        "longitude": 115.8980
      },
      {
        "latitude": -31.8800,
        "longitude": 115.8990
      },
      {
        "latitude": -31.8810,
        "longitude": 115.9000
      },
      {
        "latitude": -31.8820,
        "longitude": 115.9010
      },
      {
        "latitude": -31.8830,
        "longitude": 115.9020
      },
      {
        "latitude": -31.8840,
        "longitude": 115.9030
      },
      {
        "latitude": -31.8850,
        "longitude": 115.9040
      },
      {
        "latitude": -31.8860,
        "longitude": 115.9050
      },
      {
        "latitude": -31.8870,
        "longitude": 115.9060
      },
      {
        "latitude": -31.8880,
        "longitude": 115.9070
      },
      {
        "latitude": -31.8890,
        "longitude": 115.9080
      },
      {
        "latitude": -31.8900,
        "longitude": 115.9090
      },
      {
        "latitude": -31.8910,
        "longitude": 115.9100
      },
      {
        "latitude": -31.8920,
        "longitude": 115.9110
      },
      {
        "latitude": -31.8930,
        "longitude": 115.9120
      },
      {
        "latitude": -31.8940,
        "longitude": 115.9130
      },
      {
        "latitude": -31.8950,
        "longitude": 115.9140
      },
      {
        "latitude": -31.8960,
        "longitude": 115.9150
      },
      {
        "latitude": -31.8970,
        "longitude": 115.9160
      },
      {
        "latitude": -31.8980,
        "longitude": 115.9170
      },
      {
        "latitude": -31.8990,
        "longitude": 115.9180
      },
      {
        "latitude": -31.9000,
        "longitude": 115.9190
      },
      {
        "latitude": -31.9010,
        "longitude": 115.9200
      },
      {
        "latitude": -31.9020,
        "longitude": 115.9210
      },
      {
        "latitude": -31.9030,
        "longitude": 115.9220
      },
      {
        "latitude": -31.9040,
        "longitude": 115.9230
      },
      {
        "latitude": -31.9050,
        "longitude": 115.9240
      },
      {
        "latitude": -31.9060,
        "longitude": 115.9250
      },
      {
        "latitude": -31.9070,
        "longitude": 115.9260
      },
      {
        "latitude": -31.9080,
        "longitude": 115.9270
      },
      {
        "latitude": -31.9090,
        "longitude": 115.9280
      },
      {
        "latitude": -31.9100,
        "longitude": 115.9290
      },
      {
        "latitude": -31.9110,
        "longitude": 115.9300
      },
      {
        "latitude": -31.9120,
        "longitude": 115.9310
      },
      {
        "latitude": -31.9130,
        "longitude": 115.9320
      },
      {
        "latitude": -31.9140,
        "longitude": 115.9330
      },
      {
        "latitude": -31.9150,
        "longitude": 115.9340
      },
      {
        "latitude": -31.9160,
        "longitude": 115.9350
      },
      {
        "latitude": -31.9170,
        "longitude": 115.9360
      },
      {
        "latitude": -31.9180,
        "longitude": 115.9370
      },
      {
        "latitude": -31.9190,
        "longitude": 115.9380
      },
      {
        "latitude": -31.9200,
        "longitude": 115.9390
      },
      {
        "latitude": -31.9210,
        "longitude": 115.9400
      },
      {
        "latitude": -31.9220,
        "longitude": 115.9410
      },
      {
        "latitude": -31.9230,
        "longitude": 115.9420
      },
      {
        "latitude": -31.9240,
        "longitude": 115.9430
      },
      {
        "latitude": -31.9250,
        "longitude": 115.9440
      },
      {
        "latitude": -31.9260,
        "longitude": 115.9450
      },
      {
        "latitude": -31.9270,
        "longitude": 115.9460
      },
      {
        "latitude": -31.9280,
        "longitude": 115.9470
      },
      {
        "latitude": -31.9290,
        "longitude": 115.9480
      },
      {
        "latitude": -31.9300,
        "longitude": 115.9490
      },
      {
        "latitude": -31.9310,
        "longitude": 115.9500
      },
      {
        "latitude": -31.9320,
        "longitude": 115.9510
      },
      {
        "latitude": -31.9330,
        "longitude": 115.9520
      },
      {
        "latitude": -31.9340,
        "longitude": 115.9530
      },
      {
        "latitude": -31.9350,
        "longitude": 115.9540
      },
      {
        "latitude": -31.9360,
        "longitude": 115.9550
      },
      {
        "latitude": -31.9370,
        "longitude": 115.9560
      },
      {
        "latitude": -31.9380,
        "longitude": 115.9570
      },
      {
        "latitude": -31.9390,
        "longitude": 115.9580
      },
      {
        "latitude": -31.9400,
        "longitude": 115.9590
      },
      {
        "latitude": -31.9410,
        "longitude": 115.9600
      },
      {
        "latitude": -31.9420,
        "longitude": 115.9610
      },
      {
        "latitude": -31.9430,
        "longitude": 115.9620
      },
      {
        "latitude": -31.9440,
        "longitude": 115.9630
      },
      {
        "latitude": -31.9450,
        "longitude": 115.9640
      },
      {
        "latitude": -31.9460,
        "longitude": 115.9650
      },
      {
        "latitude": -31.9470,
        "longitude": 115.9660
      },
      {
        "latitude": -31.9480,
        "longitude": 115.9670
      },
      {
        "latitude": -31.9490,
        "longitude": 115.9680
      },
      {
        "latitude": -31.9500,
        "longitude": 115.9690
      },
      {
        "latitude": -31.9510,
        "longitude": 115.9700
      },
      {
        "latitude": -31.9520,
        "longitude": 115.9710
      },
      {
        "latitude": -31.9530,
        "longitude": 115.9720
      },
      {
        "latitude": -31.9540,
        "longitude": 115.9730
      },
      {
        "latitude": -31.9550,
        "longitude": 115.9740
      },
      {
        "latitude": -31.9560,
        "longitude": 115.9750
      },
      {
        "latitude": -31.9570,
        "longitude": 115.9760
      },
      {
        "latitude": -31.9580,
        "longitude": 115.9770
      },
      {
        "latitude": -31.9590,
        "longitude": 115.9780
      },
      {
        "latitude": -31.9600,
        "longitude": 115.9790
      },
      {
        "latitude": -31.9610,
        "longitude": 115.9800
      },
      {
        "latitude": -31.9620,
        "longitude": 115.9810
      },
      {
        "latitude": -31.9630,
        "longitude": 115.9820
      },
      {
        "latitude": -31.9640,
        "longitude": 115.9830
      },
      {
        "latitude": -31.9650,
        "longitude": 115.9840
      },
      {
        "latitude": -31.9660,
        "longitude": 115.9850
      },
      {
        "latitude": -31.9670,
        "longitude": 115.9860
      },
      {
        "latitude": -31.9680,
        "longitude": 115.9870
      },
      {
        "latitude": -31.9690,
        "longitude": 115.9880
      },
      {
        "latitude": -31.9700,
        "longitude": 115.9890
      },
      {
        "latitude": -31.9710,
        "longitude": 115.9900
      },
      {
        "latitude": -31.9720,
        "longitude": 115.9910
      },
      {
        "latitude": -31.9730,
        "longitude": 115.9920
      },
      {
        "latitude": -31.9740,
        "longitude": 115.9930
      },
      {
        "latitude": -31.9750,
        "longitude": 115.9940
      },
      {
        "latitude": -31.9760,
        "longitude": 115.9950
      },
      {
        "latitude": -31.9770,
        "longitude": 115.9960
      },
      {
        "latitude": -31.9780,
        "longitude": 115.9970
      },
      {
        "latitude": -31.9790,
        "longitude": 115.9980
      },
      {
        "latitude": -31.9800,
        "longitude": 115.9990
      },
      {
        "latitude": -31.9810,
        "longitude": 116.0000
      },
      {
        "latitude": -31.9820,
        "longitude": 116.0010
      },
      {
        "latitude": -31.9830,
        "longitude": 116.0020
      },
      {
        "latitude": -31.9840,
        "longitude": 116.0030
      },
      {
        "latitude": -31.9850,
        "longitude": 116.0040
      },
      {
        "latitude": -31.9860,
        "longitude": 116.0050
      },
      {
        "latitude": -31.9870,
        "longitude": 116.0060
      },
      {
        "latitude": -31.9880,
        "longitude": 116.0070
      },
      {
        "latitude": -31.9890,
        "longitude": 116.0080
      },
      {
        "latitude": -31.9900,
        "longitude": 116.0090
      },
            {
        "latitude": -31.9910,
        "longitude": 116.0100
      },
      {
        "latitude": -31.9920,
        "longitude": 116.0110
      },
      {
        "latitude": -31.9930,
        "longitude": 116.0120
      },
      {
        "latitude": -31.9940,
        "longitude": 116.0130
      },
      {
        "latitude": -31.9950,
        "longitude": 116.0140
      },
      {
        "latitude": -31.9960,
        "longitude": 116.0150
      },
      {
        "latitude": -31.9970,
        "longitude": 116.0160
      },
      {
        "latitude": -31.9980,
        "longitude": 116.0170
      },
      {
        "latitude": -31.9990,
        "longitude": 116.0180
      },
      {
        "latitude": -32.0000,
        "longitude": 116.0190
      },
      {
        "latitude": -32.0010,
        "longitude": 116.0200
      },
      {
        "latitude": -32.0020,
        "longitude": 116.0210
      },
      {
        "latitude": -32.0030,
        "longitude": 116.0220
      },
      {
        "latitude": -32.0040,
        "longitude": 116.0230
      },
      {
        "latitude": -32.0050,
        "longitude": 116.0240
      },
      {
        "latitude": -32.0060,
        "longitude": 116.0250
      },
      {
        "latitude": -32.0070,
        "longitude": 116.0260
      },
      {
        "latitude": -32.0080,
        "longitude": 116.0270
      },
      {
        "latitude": -32.0090,
        "longitude": 116.0280
      },
      {
        "latitude": -32.0100,
        "longitude": 116.0290
      },
      {
        "latitude": -32.0110,
        "longitude": 116.0300
      },
      {
        "latitude": -32.0120,
        "longitude": 116.0310
      },
      {
        "latitude": -32.0130,
        "longitude": 116.0320
      },
      {
        "latitude": -32.0140,
        "longitude": 116.0330
      },
      {
        "latitude": -32.0150,
        "longitude": 116.0340
      },
      {
        "latitude": -32.0160,
        "longitude": 116.0350
      },
      {
        "latitude": -32.0170,
        "longitude": 116.0360
      },
      {
        "latitude": -32.0180,
        "longitude": 116.0370
      },
      {
        "latitude": -32.0190,
        "longitude": 116.0380
      },
      {
        "latitude": -32.0200,
        "longitude": 116.0390
      },
      {
        "latitude": -32.0210,
        "longitude": 116.0400
      },
      {
        "latitude": -32.0220,
        "longitude": 116.0410
      },
      {
        "latitude": -32.0230,
        "longitude": 116.0420
      },
      {
        "latitude": -32.0240,
        "longitude": 116.0430
      },
      {
        "latitude": -32.0250,
        "longitude": 116.0440
      },
      {
        "latitude": -32.0260,
        "longitude": 116.0450
      },
      {
        "latitude": -32.0270,
        "longitude": 116.0460
      },
      {
        "latitude": -32.0280,
        "longitude": 116.0470
      },
      {
        "latitude": -32.0290,
        "longitude": 116.0480
      },
      {
        "latitude": -32.0300,
        "longitude": 116.0490
      },
      {
        "latitude": -32.0310,
        "longitude": 116.0500
      },
      {
        "latitude": -32.0320,
        "longitude": 116.0510
      },
      {
        "latitude": -32.0330,
        "longitude": 116.0520
      },
      {
        "latitude": -32.0340,
        "longitude": 116.0530
      },
      {
        "latitude": -32.0350,
        "longitude": 116.0540
      },
      {
        "latitude": -32.0360,
        "longitude": 116.0550
      },
      {
        "latitude": -32.0370,
        "longitude": 116.0560
      },
      {
        "latitude": -32.0380,
        "longitude": 116.0570
      },
      {
        "latitude": -32.0390,
        "longitude": 116.0580
      },
      {
        "latitude": -32.0400,
        "longitude": 116.0590
      },
      {
        "latitude": -32.0410,
        "longitude": 116.0600
      },
      {
        "latitude": -32.0420,
        "longitude": 116.0610
      },
      {
        "latitude": -32.0430,
        "longitude": 116.0620
      },
      {
        "latitude": -32.0440,
        "longitude": 116.0630
      },
      {
        "latitude": -32.0450,
        "longitude": 116.0640
      },
      {
        "latitude": -32.0460,
        "longitude": 116.0650
      },
      {
        "latitude": -32.0470,
        "longitude": 116.0660
      },
      {
        "latitude": -32.0480,
        "longitude": 116.0670
      },
      {
        "latitude": -32.0490,
        "longitude": 116.0680
      },
      {
        "latitude": -32.0500,
        "longitude": 116.0690
      },
      {
        "latitude": -32.0510,
        "longitude": 116.0700
      },
      {
        "latitude": -32.0520,
        "longitude": 116.0710
      },
      {
        "latitude": -32.0530,
        "longitude": 116.0720
      },
      {
        "latitude": -32.0540,
        "longitude": 116.0730
      },
      {
        "latitude": -32.0550,
        "longitude": 116.0740
      },
      {
        "latitude": -32.0560,
        "longitude": 116.0750
      },
      {
        "latitude": -32.0570,
        "longitude": 116.0760
      },
      {
        "latitude": -32.0580,
        "longitude": 116.0770
      },
      {
        "latitude": -32.0590,
        "longitude": 116.0780
      },
      {
        "latitude": -32.0600,
        "longitude": 116.0790
      },
      {
        "latitude": -32.0610,
        "longitude": 116.0800
      },
      {
        "latitude": -32.0620,
        "longitude": 116.0810
      },
      {
        "latitude": -32.0630,
        "longitude": 116.0820
      },
      {
        "latitude": -32.0640,
        "longitude": 116.0830
      },
      {
        "latitude": -32.0650,
        "longitude": 116.0840
      },
      {
        "latitude": -32.0660,
        "longitude": 116.0850
      },
      {
        "latitude": -32.0670,
        "longitude": 116.0860
      },
      {
        "latitude": -32.0680,
        "longitude": 116.0870
      },
      {
        "latitude": -32.0690,
        "longitude": 116.0880
      },
      {
        "latitude": -32.0700,
        "longitude": 116.0890
      },
      {
        "latitude": -32.0710,
        "longitude": 116.0900
      },
      {
        "latitude": -32.0720,
        "longitude": 116.0910
      },
      {
        "latitude": -32.0730,
        "longitude": 116.0920
      },
      {
        "latitude": -32.0740,
        "longitude": 116.0930
      },
      {
        "latitude": -32.0750,
        "longitude": 116.0940
      },
      {
        "latitude": -32.0760,
        "longitude": 116.0950
      },
      {
        "latitude": -32.0770,
        "longitude": 116.0960
      },
      {
        "latitude": -32.0780,
        "longitude": 116.0970
      },
      {
        "latitude": -32.0790,
        "longitude": 116.0980
      },
      {
        "latitude": -32.0800,
        "longitude": 116.0990
      },
      {
        "latitude": -32.0810,
        "longitude": 116.1000
      },
      {
        "latitude": -32.0820,
        "longitude": 116.1010
      },
      {
        "latitude": -32.0830,
        "longitude": 116.1020
      },
      {
        "latitude": -32.0840,
        "longitude": 116.1030
      },
      {
        "latitude": -32.0850,
        "longitude": 116.1040
      },
      {
        "latitude": -32.0860,
        "longitude": 116.1050
      },
      {
        "latitude": -32.0870,
        "longitude": 116.1060
      },
      {
        "latitude": -32.0880,
        "longitude": 116.1070
      },
      {
        "latitude": -32.0890,
        "longitude": 116.1080
      },
      {
        "latitude": -32.0900,
        "longitude": 116.1090
      },
      {
        "latitude": -32.0910,
        "longitude": 116.1100
      },
      {
        "latitude": -32.0920,
        "longitude": 116.1110
      },
      {
        "latitude": -32.0930,
        "longitude": 116.1120
      },
      {
        "latitude": -32.0940,
        "longitude": 116.1130
      },
      {
        "latitude": -32.0950,
        "longitude": 116.1140
      },
      {
        "latitude": -32.0960,
        "longitude": 116.1150
      },
      {
        "latitude": -32.0970,
        "longitude": 116.1160
      },
      {
        "latitude": -32.0980,
        "longitude": 116.1170
      },
      {
        "latitude": -32.0990,
        "longitude": 116.1180
      },
      {
        "latitude": -32.1000,
        "longitude": 116.1190
      },
      {
        "latitude": -32.1010,
        "longitude": 116.1200
      },
      {
        "latitude": -32.1020,
        "longitude": 116.1210
      },
      {
        "latitude": -32.1030,
        "longitude": 116.1220
      },
      {
        "latitude": -32.1040,
        "longitude": 116.1230
      },
      {
        "latitude": -32.1050,
        "longitude": 116.1240
      },
      {
        "latitude": -32.1060,
        "longitude": 116.1250
      },
      {
        "latitude": -32.1070,
        "longitude": 116.1260
      },
      {
        "latitude": -32.1080,
        "longitude": 116.1270
      },
      {
        "latitude": -32.1090,
        "longitude": 116.1280
      },
      {
        "latitude": -32.1100,
        "longitude": 116.1290
      },
      {
        "latitude": -32.1110,
        "longitude": 116.1300
      },
      {
        "latitude": -32.1120,
        "longitude": 116.1310
      },
      {
        "latitude": -32.1130,
        "longitude": 116.1320
      },
      {
        "latitude": -32.1140,
        "longitude": 116.1330
      },
      {
        "latitude": -32.1150,
        "longitude": 116.1340
      },
      {
        "latitude": -32.1160,
        "longitude": 116.1350
      },
      {
        "latitude": -32.1170,
        "longitude": 116.1360
      },
      {
        "latitude": -32.1180,
        "longitude": 116.1370
      },
      {
        "latitude": -32.1190,
        "longitude": 116.1380
      },
      {
        "latitude": -32.1200,
        "longitude": 116.1390
      },
      {
        "latitude": -32.1210,
        "longitude": 116.1400
      },
      {
        "latitude": -32.1220,
        "longitude": 116.1410
      },
      {
        "latitude": -32.1230,
        "longitude": 116.1420
      },
      {
        "latitude": -32.1240,
        "longitude": 116.1430
      },
      {
        "latitude": -32.1250,
        "longitude": 116.1440
      },
      {
        "latitude": -32.1260,
        "longitude": 116.1450
      },
      {
        "latitude": -32.1270,
        "longitude": 116.1460
      },
      {
        "latitude": -32.1280,
        "longitude": 116.1470
      },
      {
        "latitude": -32.1290,
        "longitude": 116.1480
      },
      {
        "latitude": -32.1300,
        "longitude": 116.1490
      },
      {
        "latitude": -32.1310,
        "longitude": 116.1500
      },
      {
        "latitude": -32.1320,
        "longitude": 116.1510
      },
      {
        "latitude": -32.1330,
        "longitude": 116.1520
      },
      {
        "latitude": -32.1340,
        "longitude": 116.1530
      },
      {
        "latitude": -32.1350,
        "longitude": 116.1540
      },
      {
        "latitude": -32.1360,
        "longitude": 116.1550
      },
      {
        "latitude": -32.1370,
        "longitude": 116.1560
      },
      {
        "latitude": -32.1380,
        "longitude": 116.1570
      },
      {
        "latitude": -32.1390,
        "longitude": 116.1580
      },
      {
        "latitude": -32.1400,
        "longitude": 116.1590
      },
      {
        "latitude": -32.1410,
        "longitude": 116.1600
      },
      {
        "latitude": -32.1420,
        "longitude": 116.1610
      },
      {
        "latitude": -32.1430,
        "longitude": 116.1620
      },
      {
        "latitude": -32.1440,
        "longitude": 116.1630
      },
      {
        "latitude": -32.1450,
        "longitude": 116.1640
      },
      {
        "latitude": -32.1460,
        "longitude": 116.1650
      },
      {
        "latitude": -32.1470,
        "longitude": 116.1660
      },
      {
        "latitude": -32.1480,
        "longitude": 116.1670
      },
      {
        "latitude": -32.1490,
        "longitude": 116.1680
      },
      {
        "latitude": -32.1500,
        "longitude": 116.1690
      },
      {
        "latitude": -32.1510,
        "longitude": 116.1700
      },
      {
        "latitude": -32.1520,
        "longitude": 116.1710
      },
      {
        "latitude": -32.1530,
        "longitude": 116.1720
      },
      {
        "latitude": -32.1540,
        "longitude": 116.1730
      },
      {
        "latitude": -32.1550,
        "longitude": 116.1740
      },
      {
        "latitude": -32.1560,
        "longitude": 116.1750
      },
      {
        "latitude": -32.1570,
        "longitude": 116.1760
      },
      {
        "latitude": -32.1580,
        "longitude": 116.1770
      },
      {
        "latitude": -32.1590,
        "longitude": 116.1780
      },
      {
        "latitude": -32.1600,
        "longitude": 116.1790
      },
      {
        "latitude": -32.1610,
        "longitude": 116.1800
      },
      {
        "latitude": -32.1620,
        "longitude": 116.1810
      },
      {
        "latitude": -32.1630,
        "longitude": 116.1820
      },
      {
        "latitude": -32.1640,
        "longitude": 116.1830
      },
      {
        "latitude": -32.1650,
        "longitude": 116.1840
      },
      {
        "latitude": -32.1660,
        "longitude": 116.1850
      },
      {
        "latitude": -32.1670,
        "longitude": 116.1860
      },
      {
        "latitude": -32.1680,
        "longitude": 116.1870
      },
      {
        "latitude": -32.1690,
        "longitude": 116.1880
      },
      {
        "latitude": -32.1700,
        "longitude": 116.1890
      },
      {
        "latitude": -32.1710,
        "longitude": 116.1900
      },
      {
        "latitude": -32.1720,
        "longitude": 116.1910
      },
      {
        "latitude": -32.1730,
        "longitude": 116.1920
      },
      {
        "latitude": -32.1740,
        "longitude": 116.1930
      },
      {
        "latitude": -32.1750,
        "longitude": 116.1940
      },
      {
        "latitude": -32.1760,
        "longitude": 116.1950
      },
      {
        "latitude": -32.1770,
        "longitude": 116.1960
      },
      {
        "latitude": -32.1780,
        "longitude": 116.1970
      },
      {
        "latitude": -32.1790,
        "longitude": 116.1980
      },
      {
        "latitude": -32.1800,
        "longitude": 116.1990
      },
      {
        "latitude": -32.1810,
        "longitude": 116.2000
      },
      {
        "latitude": -32.1820,
        "longitude": 116.2010
      },
      {
        "latitude": -32.1830,
        "longitude": 116.2020
      },
      {
        "latitude": -32.1840,
        "longitude": 116.2030
      },
      {
        "latitude": -32.1850,
        "longitude": 116.2040
      },
      {
        "latitude": -32.1860,
        "longitude": 116.2050
      },
      {
        "latitude": -32.1870,
        "longitude": 116.2060
      },
      {
        "latitude": -32.1880,
        "longitude": 116.2070
      },
      {
        "latitude": -32.1890,
        "longitude": 116.2080
      },
      {
        "latitude": -32.1900,
        "longitude": 116.2090
      },
      {
        "latitude": -32.1910,
        "longitude": 116.2100
      },
      {
        "latitude": -32.1920,
        "longitude": 116.2110
      },
      {
        "latitude": -32.1930,
        "longitude": 116.2120
      },
      {
        "latitude": -32.1940,
        "longitude": 116.2130
      },
      {
        "latitude": -32.1950,
        "longitude": 116.2140
      },
      {
        "latitude": -32.1960,
        "longitude": 116.2150
      },
      {
        "latitude": -32.1970,
        "longitude": 116.2160
      },
      {
        "latitude": -32.1980,
        "longitude": 116.2170
      },
      {
        "latitude": -32.1990,
        "longitude": 116.2180
      },
      {
        "latitude": -32.2000,
        "longitude": 116.2190
      },
      {
        "latitude": -32.2010,
        "longitude": 116.2200
      },
      {
        "latitude": -32.2020,
        "longitude": 116.2210
      },
      {
        "latitude": -32.2030,
        "longitude": 116.2220
      },
      {
        "latitude": -32.2040,
        "longitude": 116.2230
      },
      {
        "latitude": -32.2050,
        "longitude": 116.2240
      },
      {
        "latitude": -32.2060,
        "longitude": 116.2250
      },
      {
        "latitude": -32.2070,
        "longitude": 116.2260
      },
      {
        "latitude": -32.2080,
        "longitude": 116.2270
      },
      {
        "latitude": -32.2090,
        "longitude": 116.2280
      },
      {
        "latitude": -32.2100,
        "longitude": 116.2290
      },
      {
        "latitude": -32.2110,
        "longitude": 116.2300
      },
      {
        "latitude": -32.2120,
        "longitude": 116.2310
      },
      {
        "latitude": -32.2130,
        "longitude": 116.2320
      },
      {
        "latitude": -32.2140,
        "longitude": 116.2330
      },
      {
        "latitude": -32.2150,
        "longitude": 116.2340
      },
      {
        "latitude": -32.2160,
        "longitude": 116.2350
      },
      {
        "latitude": -32.2170,
        "longitude": 116.2360
      },
      {
        "latitude": -32.2180,
        "longitude": 116.2370
      },
      {
        "latitude": -32.2190,
        "longitude": 116.2380
      },
      {
        "latitude": -32.2200,
        "longitude": 116.2390
      },
      {
        "latitude": -32.2210,
        "longitude": 116.2400
      },
      {
        "latitude": -32.2220,
        "longitude": 116.2410
      },
      {
        "latitude": -32.2230,
        "longitude": 116.2420
      },
      {
        "latitude": -32.2240,
        "longitude": 116.2430
      },
      {
        "latitude": -32.2250,
        "longitude": 116.2440
      },
      {
        "latitude": -32.2260,
        "longitude": 116.2450
      },
      {
        "latitude": -32.2270,
        "longitude": 116.2460
      },
      {
        "latitude": -32.2280,
        "longitude": 116.2470
      },
      {
        "latitude": -32.2290,
        "longitude": 116.2480
      },
      {
        "latitude": -32.2300,
        "longitude": 116.2490
      },
      {
        "latitude": -32.2310,
        "longitude": 116.250
    }
    ]
    }
]
    return jsonify(hikes)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
