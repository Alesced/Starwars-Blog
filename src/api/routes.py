"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User, Planets, Characters, Starship
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
import requests 
from flask_cors import CORS

api = Blueprint('api', __name__)
bcrypt = Bcrypt()
# Allow CORS requests to this API
CORS(api)



@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

#-----------------------------------Routes for register-------------------------------------
@api.route('/register', methods=['POST'])
def user_register(): 
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        username = data.get('username')
        first_name = data.get('first_name')
        last_name = data.get('last_name')

        required_fields = ['email', 'password', 'username', 'first_name', 'last_name']

        if not all(field in data for field in required_fields):
            return jsonify({"msg": "All fields are required"}), 400
        
        email = data['email']
        password = data['password']
        username = data['username']
        first_name = data['first_name']
        last_name = data['last_name']

        if User.query.filter_by(email=email).first():
            return jsonify({'msg': 'Email already exists'}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({'msg': 'Username already exists'}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        new_user = User(
            email=email,
            password=hashed_password,
            username=username,
            first_name=first_name,
            last_name=last_name
        )
        db.session.add(new_user)
        db.session.commit()

        # Generate JWT token
        create_access_token(identity={'id': new_user.id})

        return jsonify({
            'msg': 'User registered successfully',
            'user': {
                'id': new_user.id,
                'email': new_user.email,
                'username': new_user.username,
                'first_name': new_user.first_name,
                'last_name': new_user.last_name
            },
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Error in request data", "details": str(e)}), 500

#-----------------------------------Routes for Login-----------------------------------
@api.route(('/login'), methods=['POST'])
def user_login():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not (email or username) or not password:
            return jsonify({"msg": "Email or username and password are required"}), 400
        
        user = User.query.filter_by(email=email).first() if email else User.query.filter_by(username=username).first()

        if not user or not bcrypt.check_password_hash(user.password, password):
            return jsonify({"msg": "Invalid credentials"}), 401
        
        access_token = create_access_token(identity={'id': user.id})

        #Serialize for favorites of the user
        favorites_characters = [fav.serialize() for fav in user.favorites_characters.all()]
        favorites_planets = [fav.serialize() for fav in user.favorites_planets.all()]
        starships_favorites = [fav.serialize() for fav in user.starships_favorites.all()]

        return jsonify({
            'token': access_token,
            'user_id': user.id,
            'email': user.email,
            'username': user.username,
            'favorite': {
                'characters': favorites_characters,  
                'planets': favorites_planets,
                'starships': starships_favorites
            }
        })
        
    
    except Exception as e:
        return jsonify({"msg": "Login failed", "details": str(e)}), 500
   

#-----------------------------------Routes for Characters-----------------------------------
@api.route('/characters', methods=['GET'])
@jwt_required()
def get_all_characters():
    try:
        response = requests.get(f"https://swapi.tech/api/people/")

        if response.status_code != 200:
            return jsonify({"msg": "Error fetching characters"}), response.status_code
        
        characters_data = response.json().get('results', [])
        
        return jsonify(characters_data), 200

    except Exception as e:
        return jsonify({"msg": "Error retrieving characters", "details": str(e)}), 500

#-----------------------------------Routes for Characters by ID-----------------------------------
@api.route('/characters/<int:character_id>', methods=['GET'])
@jwt_required()
def get_character_by_id(character_id):
    try:
        response = requests.get(f"https://swapi.tech/api/people/{character_id}")

        if response.status_code != 200:
            return jsonify({"msg": "Character not found"}), 404
        
        character_data = response.json()
        
        #verificar si es favorito del usuario autenticado
        is_favorite = False 
        current_user = get_jwt_identity()
        if current_user:
            user = User.query.get(current_user['id'])
            is_favorite = user.favorites_characters.filter_by(id=character_id).first() is not None

        return jsonify({
            "is_favorite": is_favorite,
            "character": character_data
        }), 200

    except Exception as e:
        return jsonify({"msg": "Error retrieving character", "details": str(e)}), 500

#-----------------------------------Routes for Planets-----------------------------------
@api.route('/planets', methods=['GET'])
@jwt_required()
def get_all_planets():
    try:
        response = requests.get("https://swapi.tech/api/planets/")

        if response.status_code != 200:
            return jsonify({'msg': 'Error fetching planets'}), response.status_code
        
        planets_data = response.json().get('results', [])

        return jsonify(planets_data), 200
    
    except Exception as e:
        return jsonify({"msg": "Error retrieving planets", "details": str(e)}), 500

#-----------------------------------Routes for Planets by ID-----------------------------------
@api.route('/planets/<int:planet_id>', methods=['GET'])
@jwt_required()
def get_planet_by_id(planet_id):
    try:
        response = requests.get(f"https://swapi.tech/api/planets/{planet_id}")

        if response.status_code != 200:
            return jsonify({"msg": "Planet not found"}), 404
        
        planet_data = response.json()

        #verificar si es favorito del usuario autenticado
        is_favorite = False
        current_user = get_jwt_identity()

        if current_user:
            user = User.query.get(current_user['id'])
            is_favorite = user.favorites_planets.filter_by(id=planet_id).first() is not None
            
        return jsonify({
            "is_favorite": is_favorite,
            "planet": planet_data
        }), 200

    except Exception as e:
        return jsonify({"msg": "Error retrieving planet", "details": str(e)}), 500

#-----------------------------------Routes for Starships-----------------------------------
@api.route('/starships', methods=['GET'])
@jwt_required()
def get_all_starships():
    try:
        response = requests.get("https://swapi.tech/api/starships/")

        if response.status_code != 200:
            return jsonify({"msg": "Error fetching starships"}), response.status_code
        
        starships_data = response.json().get('results', [])

        return jsonify(starships_data), 200
    
    except Exception as e:
        return jsonify({"msg": "Error retrieving starships", "details": str(e)}), 500
    

#-----------------------------------Routes for Starships by ID-----------------------------------
@api.route('/starships/<int:starship_id>', methods=['GET'])
@jwt_required()
def get_starship_by_id(starship_id):
    try:
        response = requests.get(f"https://swapi.tech/api/starships/{starship_id}")

        if response.status_code != 200:
            return jsonify({"msg": "Starship not found"}), 404
        
        starship_data = response.json()
        
        #verificar si es favorito del usuario autenticado
        is_favorite = False
        current_user = get_jwt_identity()   

        if current_user:
            user = User.query.get(current_user['id'])
            is_favorite = user.starships_favorites.filter_by(id=starship_id).first() is not None
            
        return jsonify({
            "is_favorite": is_favorite,
            "starship": starship_data
        }), 200
    
    except Exception as e:
        return jsonify({"msg": "Error retrieving starship", "details": str(e)}), 500

#-----------------------------------Routes for User Profile-----------------------------------
@api.route('/users/<int:user_id>', methods=['GET', 'PUT'])
@jwt_required()
def get_user_profile(user_id):
    try:
        current_user = get_jwt_identity()
        
        if not current_user or current_user['id'] != user_id:
            return jsonify({"msg": "Unauthorized access"}), 403
        
        user = User.query.get(user_id)

        if not user:
            return jsonify({"msg": "User not found"}), 404
        
        if request.method == 'GET':
            return jsonify(user.serialize()), 200
        
        elif request.method == 'PUT':
            data = request.json
            if not data:
                return jsonify({"msg": "No data provided"}), 400
            
            updated_fields = ['email', 'username', 'first_name', 'last_name']

            updated = False

            for fields in updated_fields:
                if fields in data:
                    current_value = getattr(user, fields)
                    new_value = data[fields]

                    if current_value != new_value:
                        setattr(user, fields, new_value)
                        updated = True

            if updated:
                db.session.commit()
                return jsonify({
                    "msg": "User profile updated successfully", 
                    "user": user.serialize()
                }), 200
            else:
                return jsonify({"msg": "No changes detected"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Error retrieving user profile", "details": str(e)}), 500

#-----------------------------------Routes for Adding ande delete Favorites Planets-----------------------------------
@api.route('/favorite/planet/<int:planet_id>', methods=['POST', 'DELETE'])
@jwt_required()
def add_favorite_planet(planet_id):
    try:
        current_user = get_jwt_identity()
        user = User.query.get(current_user['id'])
        planet = Planets.query.get(planet_id)

        if not user or not planet:
            return jsonify({"msg": "User or planet not found"}), 404
        
        if request.method == 'POST':
            if planet in user.favorites_planets:
                return jsonify({"msg": "Planet already in favorites"}), 400
            
            if planet not in user.favorites_planets:
                user.favorites_planets.append(planet)
                db.session.commit()
                
                return jsonify({
                    "msg": "Planet added to favorites", 
                    "new_planet": planet.serialize()
                }), 201
        
        elif request.method == 'DELETE':
            favorites = user.favorites_planets.filter_by(id=planet_id).first()

            if not favorites:
                return jsonify({"msg": "Planet not in favorites"}), 400
            
            db.session.delete(favorites)
            db.session.commit()

            return jsonify({"msg": "Planet removed from favorites"}), 200
    
    except Exception as e:
        return jsonify({"msg": "Error retrieving user or planet", "details": str(e)}), 500

#-----------------------------------Routes for Adding and Favorites Characters-----------------------------------
@api.route('/favorite/character/<int:character_id>', methods=['POST', 'DELETE'])
@jwt_required()
def add_favorite_characther(character_id):
    try:
        current_user = get_jwt_identity()
        user = User.query.get(current_user['id'])
        character = Characters.query.get(character_id)

        if not user or not character:
            return jsonify({"msg": "User or character not found"}), 404
        
        if request.method == 'POST':
            if character in user.favorites_characters:
                return jsonify({"msg": "Character already in favorites"}), 400
            
            user.favorites_characters.append(character)
            db.session.commit()
            return jsonify({
                "msg": "Character added to favorites", 
                "new_character": character.serialize()
            }), 201
        
        elif request.method == 'DELETE':
            character = user.favorites_characters.filter_by(id=character_id).first()

            if not character:
                return jsonify({"msg": "Character not in favorites"}), 400

            db.session.delete(character)
            db.session.commit()
            
            return jsonify({"msg": "Character removed from favorites"}), 200 
    
    except Exception as e:
        return jsonify({"msg": "Error retrieving user or character", "details": str(e)}), 500

#-----------------------------------Routes for Adding Favorites Starships-----------------------------------
@api.route('/favorite/starship/<int:starship_id>', methods=['POST'])
@jwt_required()
def add_favorite_starship(starship_id):
    try:
        current_user = get_jwt_identity()
        user = User.query.get(current_user['id'])
        starship = Starship.query.get(starship_id)

        if not user or not starship:
            return jsonify({"msg": "User or starship not found"}), 404

        if request.method == 'POST':
            if starship in user.starship_favorites:
                return jsonify({"msg": "Starship already in favorites"}), 400

            user.starships_favorites.append(starship)
            db.session.commit()
           
            return jsonify({
                "msg": "Starship added to favorites", 
                "new_favorite": starship.serialize()
            }), 201

        elif request.method == 'DELETE':
            starship = user.starships_favorites.filter_by(id=starship_id).first()

            if not starship:
                return jsonify({"msg": "Starship not in favorites"}), 400

            db.session.delete(starship)
            db.session.commit()

            return jsonify({"msg": "Starship removed from favorites"}), 200

    except Exception as e:
        return jsonify({"msg": "Error retrieving user or starship", "details": str(e)}), 500
