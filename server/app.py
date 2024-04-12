#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from werkzeug.security import generate_password_hash, check_password_hash

from config import app, db, api
from models import User, Recipe
 
import bcrypt            
class Signup(Resource):
    def post(self):
        user_data = request.get_json()
        if not user_data or 'username' not in user_data or 'password' not in user_data:
            return {'error': 'Missing username or password'}, 422
        if User.query.filter_by(username=user_data['username']).first():
            return {'error': 'Username already exists'}, 422
        new_user = User(username=user_data['username'])
        # Hash the password before storing it
        hashed_password = generate_password_hash(user_data['password'])
        new_user.password_hash = hashed_password
        db.session.add(new_user)
        db.session.commit()
        return {'message': 'Signup successful'
        }, 201

class Login(Resource):
    def post(self):
        user_data = request.get_json()
        if not user_data or 'username' not in user_data or 'password' not in user_data:
            return {'error': 'Missing username or password'}, 422
        user = User.query.filter_by(username=user_data['username']).first()
        if not user or not check_password_hash(user.password_hash, user_data['password']):
            return {'error': 'Invalid username or password'}, 401
        session['user_id'] = user.id
        return {'message': 'Login successful'
        }, 200

class CheckSession(Resource):
    def get(self):
        if 'user_id' not in session:
            return {'error': 'Not logged in'}, 401
        
        user_id = session['user_id']
        
        if user_id is None:
            return {'error': 'Invalid user ID in session'}, 401
        
        user = db.session.get(User, user_id)
        
        if user is None:
            return {'error': 'User not found'}, 401
        
        return {
            'id': user.id,
            'username': user.username,
            'image_url': user.image_url,
            'bio': user.bio
        }, 200       
        
class Logout(Resource):
    def delete(self):
        session['user_id']=  None
        return {}, 401
    pass
              
class RecipeIndex(Resource):
    def get(self):
        if 'user_id' not in session:
            return {'error': 'Not logged in'}, 401
        user_id = session['user_id']
        recipes = Recipe.query.filter_by(user_id=user_id).all()  # Only fetch recipes for the logged-in user
        recipe_data = [{'id': r.id, 'title': r.title, 'instructions': r.instructions, 'minutes_to_complete': r.minutes_to_complete, 'user': {'id': r.user.id, 'username': r.user.username, 'bio': r.user.bio, 'image_url': r.user.image_url}} for r in recipes]
        return recipe_data, 200

    def post(self):
        if 'user_id' not in session:
            return {'error': 'Not logged in'}, 401
        user = User.query.get(session['user_id'])
        recipe_data = request.get_json()
        recipe = Recipe(title=recipe_data['title'], instructions=recipe_data['instructions'], minutes_to_complete=recipe_data['minutes_to_complete'], user=user)
        db.session.add(recipe)
        if not recipe.title or not recipe.instructions or not recipe.minutes_to_complete:
            db.session.rollback()
            return {'error': 'Recipe data is invalid'}, 422
        db.session.commit()
        return {'id': recipe.id, 'title': recipe.title, 'instructions': recipe.instructions, 'minutes_to_complete': recipe.minutes_to_complete, 'user': {'id': recipe.user.id, 'username': recipe.user.username, 'bio': recipe.user.bio, 'image_url': recipe.user.image_url}}, 201

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)