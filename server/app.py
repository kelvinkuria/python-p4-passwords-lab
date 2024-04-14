#!/usr/bin/env python3
from flask import request, session, jsonify
from flask_restful import Resource
from config import app, db, api, bcrypt
from models import User

class ClearSession(Resource):
    def delete(self):
        session['page_views'] = None
        session['user_id'] = None
        return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()
        username = json['username']
        password = json['password']
        confirm_password = json.get('confirmPassword')

        if not username or not password or not confirm_password:
            return jsonify({"error": "Please provide username, password, and confirmPassword"}), 400

        if password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({"error": "Username already exists"}), 409

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id

        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return jsonify(user.to_dict()), 200
        return jsonify({}), 204

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        if not username or not password:
            return jsonify({"error": "Please provide username and password"}), 400

        user = User.query.filter_by(username=username).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            return jsonify({"error": "Invalid username or password"}), 401

        session['user_id'] = user.id

        return jsonify(user.to_dict()), 200

class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)
        return jsonify({}), 204

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
