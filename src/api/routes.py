"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User, Planets, Characters, Starship, favorites_characters, favorites_planets, starships_favorites
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token
from flas_bcrypt import Bcrypt, generate_password_hash, check_password_hash
from flask_cors import CORS

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)
bcrypt = Bcrypt()


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

#-----------------------------------Routes for token generation-------------------------------------
@api.route('/token', methods=['POST'])
def generate_token():
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(email=email, username=username, password=password).first()
    if not user:
        return jsonify({"msg": "Invalid credentials"}), 401
    
    access_token = create_access_token(identity={'id': user.id})
    return jsonify({'token': access_token, 'user_id': user.id}), 200

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

        if not [email, password, username, first_name, last_name]:
            return jsonify({"msg": "All fields are required"}), 400

        if User.query.filter_by(email=email).firtst():
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
                'email': email,
                'username': username,
                'first_name': first_name,
                'last_name': last_name
            }
        }), 201

    except Exception as e:
        return jsonify({"msg": "Error in request data"}), 400

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
        return jsonify({"msg": "Error in request data"}), 400
   

#-----------------------------------Routes for Characters-----------------------------------
@api.route('/characters', methods=['GET'])
def get_all_characters():
    characthers = Characters.query.all()
    return jsonify([characters.serialize() for characters in characthers])

#-----------------------------------Routes for Characters by ID-----------------------------------
@api.route('/characters/>int:character_id', methods=['GET'])
def get_character_by_id(character_id):
    character = Characters.query.get(character_id)
    if not character:
        return jsonify({"msg": "Character not found"}), 404
    return jsonify(character.serialize()), 200

#-----------------------------------Routes for Planets-----------------------------------
@api.route('/planets', methods=['GET'])
def get_all_planets():
    planets = Planets.query.all()
    return jsonify([planets.serialize() for planets in planets]), 200

#-----------------------------------Routes for Planets by ID-----------------------------------
@api.route('/planets/<int:planet_id>', methods=['GET'])
def get_planet_by_id(planet_id):
    planet = Planets.query.get(planet_id)
    if not planet:
        return jsonify({"msg": "Planet not found"}), 404
    return jsonify(planet.serialize()), 200

#-----------------------------------Routes for Starships-----------------------------------
@api.route('/starships', methods=['GET'])
def get_all_starships():
    starships = Starship.query.all()
    return jsonify([starship.serialize() for starship in starships]), 200

#-----------------------------------Routes for Starships by ID-----------------------------------
@api.route('/starships/<int:starship_id>', methods=['GET'])
def get_starship_by_id(starship_id):
    starship = Starship.query.get(starship_id)
    if not starship:
        return jsonify({"msg": "Starship not found"}), 404
    return jsonify(starship.serialize()), 200

#-----------------------------------Routes for User-----------------------------------
@api.route('/users', methods=['GET'])
def get_all_users():
    users = User.query.all()
    return jsonify([user.serialize() for user in users]), 200

#-----------------------------------Routes for User Favorites List-----------------------------------
@api.route('/users/<int:user_id>/favorites', methods=['GET'])
def get_favorites(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    favorites = {
    "characters": [c.serialize() for c in user.favorites_characters.all()],
    "planets": [p.serialize() for p in user.favorites_planets.all()],
    "starships": [s.serialize() for s in user.starships_favorites.all()]
}
    return jsonify(favorites), 200
#-----------------------------------Routes for Adding User-----------------------------------
@api.route('/users', methods=['POST'])
def add_user():
    data = request.json
    required_fields = ('email', 'password', 'first_name', 'last_name')
    if not data or not all(field in data for field in required_fields):
        return jsonify({'msg': 'All fields are required'}), 400
    new_user = User(email=data['email'],
                    password=data['password'],
                    first_name=data['first_name'],
                    last_name=data['last_name'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify(new_user.serialize()), 201

#------------------------------------Routes for Adding Characters-----------------------------------------
@api.route('/characters', methods=['POST'])
def add_character():
    data = request.json
    required_fields = ('name','species' 'description', 'homeworld')
    if not data or not all(field in data for field in required_fields):
        return jsonify({'msg': 'All fields are required'}), 400
    new_character = Characters(name=data['name'],
                              species=data['species'],
                              description=data.get('description'),
                              homeworld=data.get('homeworld'))
    db.session.add(new_character)
    db.session.commit()
    return jsonify(new_character.serialize()), 201
#------------------------------------Routes for Adding Planets-----------------------------------------
@api.route('/planets', methods=['POST'])
def add_planet():
    data = request.json
    required_fields = ('name', 'climate', 'terrain', 'population')
    if not data or not all(field in data for field in required_fields):
        return jsonify({'msg': 'All fields are required'}), 400
    new_planet = Planets(name=data['name'],
                        climate=data['climate'],
                        terrain=data['terrain'],
                        population=data['population'])
    db.session.add(new_planet)
    db.session.commit()
    return jsonify(new_planet.serialize()), 201
#------------------------------------Routes for Adding Starships-----------------------------------------
@api.route('/starships', methods=['POST'])
def add_starship(): 
    data = request.json
    required_fields = ('name', 'model', 'starship_class')
    if not data or not all(field in data for field in required_fields):
        return jsonify({'msg': 'All fields are required'}), 400
    new_starship = Starship(name=data['name'],
                            model=data['model'],
                            starship_class=data['starship_class'])
    db.session.add(new_starship)
    db.session.commit()
    return jsonify(new_starship.serialize()), 201
#-----------------------------------Routes for Adding Favorites Planets-----------------------------------
@api.route('/favorite/planet/<int:planet_id>', methods=['POST'])
def add_favorite_planet(planet_id):
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({'msg': 'User id is required'}), 400
    
    user = User.query.get(user_id)
    planet = Planets.query.get(planet_id)
    if not user or not planet:
        return jsonify({'msg': 'User or Planet not found'}), 404
    
    if planet in user.favorites_planets:
        return jsonify({'msg': 'Planet already in favorites'}), 400
    user.favorites_planets.append(planet)

    db.session.commit()
    return jsonify({'msg': 'Planet added to favorites'}), 201

#-----------------------------------Routes for Adding Favorites Characters-----------------------------------
@api.route('/favorite/character/<int:character_id>', methods=['POST'])
def add_favorite_characther(character_id):
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({'msg': 'User id es required'}), 400
    
    user = User.query.get(user_id)
    character = Characters.query.get(character_id)
    if not user or not character:
        return jsonify({'msg': 'User or Character not found'}), 404
    
    if character in user.favorites_characters:
        return jsonify({'msg': 'Character already in favorites'}), 400
    user.favorites_characters.append(character)

    db.session.commit()
    return jsonify({'msg': 'Character added to favorites'}), 201

#-----------------------------------Routes for Adding Favorites Starships-----------------------------------
@api.route('/favorite/starship/<int:starship_id>', methods=['POST'])
def add_favorite_starship(starship_id):
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({'msg': 'User id is required'}), 400
    
    user = User.query.get(user_id)
    starship = Starship.query.get(starship_id)
    if not user or not starship:
        return jsonify({'msg': 'User or Starship nor found'}), 404
    
    if starship in user.starships_favorites:
        return jsonify({'msg': 'Starship already in favorites'}), 400
    user.starships_favorites.append(starship)

    db.session.commit()
    return jsonify({'msg': 'Starship added to favorites'}), 201

#-----------------------------------Routes for Deleting Favorites Planets-----------------------------------
@api.route('/favorite/planet/<int:planet_id>', methods=['DELETE'])
def delete_favorite_planet(planet_id):
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({'msg': 'User id is required'}), 400
    
    user = User.query.get(user_id)
    planet = Planets.query.get(planet_id)
    if not user or not planet:
        return jsonify({'msg': 'User or Planet not found'}), 404
    
    if planet not in user.favorites_planets:
        return jsonify({'msg': 'Planet not in favorites'}), 400
    user.favorites_planets.remove(planet)

    db.session.commit()
    return jsonify({'msg': 'Planet removed from favorites'}), 200

#-----------------------------------Routes for Deleting Favorites Characters-----------------------------------
@api.route('/favorite/character/<int:character_id>', methods=['DELETE'])
def delete_favorite_character(character_id):
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({'msg': 'User id is required'}), 400
    
    user = User.query.get(user_id)
    character = Characters.query.get(character_id)
    if not user or not character:
        return jsonify({'msg': 'User or Character not found'}), 404
    
    if character not in user.favorites_characters:
        return jsonify({'msg': 'Character not in favorites'}), 400
    user.favorites_characters.remove(character)

    db.session.commit()
    return jsonify({'msg': 'Character removed from favorites'}), 200

#-----------------------------------Routes for Deleting Favorites Starships-----------------------------------
@api.route('/favorite/starship/<int:starship_id>', methods=['DELETE'])
def delete_favorite_starship(starship_id):
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({'msg': 'User id is required'}), 400
    
    user = User.query.get(user_id)
    starship = Starship.query.get(starship_id)
    if not user or not starship:
        return jsonify({'msg': 'User or Starship not found'}), 404
    
    if starship not in user.starships_favorites:
        return jsonify({'msg': 'Starship not in favorites'}), 400
    user.starships_favorites.remove(starship)

    db.session.commit()
    return jsonify({'msg': 'Starship removed from favorites'}), 200
