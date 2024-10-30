#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url', '')
        bio = data.get('bio', '')

        # Validate user data here
        errors = {}
        if not username:
            errors['username'] = 'Username is required.'
        if not password:
            errors['password'] = 'Password is required.'
        
        if errors:
            return jsonify({'errors': errors}), 422  # Unprocessable Entity

        # Create a new user instance
        new_user = User(
            username=username,
            password=generate_password_hash(password), 
            image_url=image_url,
            bio=bio
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            
            return jsonify({
                'id': new_user.id,
                'username': new_user.username,
                'image_url': new_user.image_url,
                'bio': new_user.bio
            }), 201  # Created
        except Exception as e:
            return jsonify({'error': str(e)}), 500  # Internal Server Error

class CheckSession(Resource):
    def get(self):
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            return jsonify({
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }), 200
        return jsonify({'error': 'Unauthorized'}), 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(password):  
            session['user_id'] = user.id
            return jsonify({
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            })
        return jsonify({'error': 'Unauthorized'}), 401

class Logout(Resource):
    def delete(self):
        if 'user_id' in session:
            session.pop('user_id', None) 
            return '', 204  
        return jsonify({'error': 'Unauthorized'}), 401

class RecipeIndex(Resource):
    def get(self):
        if 'user_id' in session:
            recipes = Recipe.query.all()
            return jsonify([{
                'title': recipe.title,
                'instructions': recipe.instructions,
                'minutes_to_complete': recipe.minutes_to_complete,
                'user': {
                    'id': recipe.user.id,
                    'username': recipe.user.username  
                }
            } for recipe in recipes]), 200
        return jsonify({'error': 'Unauthorized'}), 401

    def post(self):
        if 'user_id' in session:
            data = request.get_json()
            title = data.get('title')
            instructions = data.get('instructions')
            minutes_to_complete = data.get('minutes_to_complete')

            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=session['user_id']  
            )
            try:
                db.session.add(recipe)
                db.session.commit()
                return jsonify({
                    'title': recipe.title,
                    'instructions': recipe.instructions,
                    'minutes_to_complete': recipe.minutes_to_complete,
                    'user': {
                        'id': recipe.user.id,
                        'username': recipe.user.username
                    }
                }), 201
            except IntegrityError:
                db.session.rollback()
                return jsonify({'errors': 'Recipe is not valid'}), 422
        return jsonify({'error': 'Unauthorized'}), 401

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)