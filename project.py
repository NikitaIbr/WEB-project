#Проект WEB Ибрагимов Никита

import os
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List, Dict, Any
from functools import wraps
import hashlib

from flask import Flask, request, jsonify, make_response
from flask_restx import Api, Resource, fields, Namespace
from flask_sqlalchemy import SQLAlchemy
from flask_caching import Cache
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    create_refresh_token, get_jwt_identity, get_jwt
)
from pydantic import BaseModel, validator, Field, confloat
import requests
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from prometheus_client import make_wsgi_app, Counter, Histogram
from werkzeug.middleware.dispatcher import DispatcherMiddleware

# --- Конфигурация ---
load_dotenv()

app = Flask(__name__)
app.config.update({
    'SQLALCHEMY_DATABASE_URI': os.getenv('DATABASE_URL', 'postgresql://user:pass@localhost:5432/yamaps_api'),
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY', 'super-secret-jwt-key-12345'),
    'JWT_ACCESS_TOKEN_EXPIRES': timedelta(minutes=15),
    'JWT_REFRESH_TOKEN_EXPIRES': timedelta(days=30),
    'CACHE_TYPE': 'RedisCache',
    'CACHE_REDIS_URL': os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
    'CACHE_DEFAULT_TIMEOUT': 3600,
    'YANDEX_MAPS_API_KEY': 'f3a0fe3a-b07e-4840-a1da-06f18b2ddf13',
    'YANDEX_GEOCODE_API': 'https://geocode-maps.yandex.ru/1.x/',
    'YANDEX_ROUTER_API': 'https://api.routing.yandex.net/v2/route',
    'METRICS_ENABLED': True
})

# --- Инициализация расширений ---
api = Api(app,
          title='Yandex Maps Extended API',
          version='1.0',
          description='Расширенный API для работы с Яндекс.Картами',
          doc='/docs/')

db = SQLAlchemy(app)
cache = Cache(app)
jwt = JWTManager(app)

# --- Настройка метрик ---
REQUEST_COUNT = Counter(
    'api_requests_total',
    'Total API requests',
    ['method', 'endpoint', 'status']
)
REQUEST_TIME = Histogram(
    'api_request_duration_seconds',
    'API request duration',
    ['endpoint']
)

# --- Логирование ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('api.log', maxBytes=1_000_000, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# --- Модели данных ---
class UserRole(str, Enum):
    USER = 'user'
    MODERATOR = 'moderator'
    ADMIN = 'admin'


class PlaceCategory(str, Enum):
    HOME = 'home'
    WORK = 'work'
    LEISURE = 'leisure'
    SHOP = 'shop'
    OTHER = 'other'


# --- Pydantic модели ---
class Location(BaseModel):
    lat: confloat(ge=-90, le=90) = Field(..., alias='latitude')
    lon: confloat(ge=-180, le=180) = Field(..., alias='longitude')
    address: Optional[str] = Field(None, max_length=200)

    class Config:
        allow_population_by_field_name = True


class RouteRequest(BaseModel):
    origin: Location
    destination: Location
    mode: str = 'car'

    @validator('mode')
    def validate_mode(cls, v):
        if v not in ['car', 'pedestrian', 'public', 'bicycle']:
            raise ValueError('Invalid transport mode')
        return v


class FavoritePlace(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    location: Location
    category: PlaceCategory = PlaceCategory.OTHER
    tags: List[str] = []


# --- SQLAlchemy модели ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default=UserRole.USER, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    favorites = db.relationship('FavoritePlace', backref='user', lazy=True)
    requests = db.relationship('ApiRequest', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()


class FavoritePlace(db.Model):
    __tablename__ = 'favorite_places'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    lat = db.Column(db.Float, nullable=False)
    lon = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(200))
    category = db.Column(db.String(20), default=PlaceCategory.OTHER)
    tags = db.Column(db.JSON, default=[])
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    visit_count = db.Column(db.Integer, default=0)


class ApiRequest(db.Model):
    __tablename__ = 'api_requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    endpoint = db.Column(db.String(50), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    params = db.Column(db.JSON)
    status_code = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# --- Декораторы ---
def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            current_user = User.query.filter_by(username=get_jwt_identity()).first()
            if current_user.role != role and current_user.role != UserRole.ADMIN:
                abort(403, message=f"Requires {role} role")
            return fn(*args, **kwargs)

        return decorator

    return wrapper


def track_request(fn):
    @wraps(fn)
    def decorated(*args, **kwargs):
        start_time = datetime.now()

        try:
            response = fn(*args, **kwargs)
            duration = (datetime.now() - start_time).total_seconds()

            # Логирование запроса
            if get_jwt_identity():
                user = User.query.filter_by(username=get_jwt_identity()).first()
                if user:
                    req = ApiRequest(
                        user_id=user.id,
                        endpoint=request.path,
                        method=request.method,
                        params=request.args.to_dict(),
                        status_code=response[1]
                    )
                    db.session.add(req)
                    db.session.commit()

            # Метрики
            REQUEST_TIME.labels(request.path).observe(duration)
            REQUEST_COUNT.labels(request.method, request.path, response[1]).inc()

            return response
        except Exception as e:
            REQUEST_COUNT.labels(request.method, request.path, 500).inc()
            raise e

    return decorated


# --- Сервисный слой ---
class YandexMapsService:
    @staticmethod
    @cache.memoize(timeout=86400)  # Кэш на 1 день
    def geocode(address: str) -> Optional[Location]:
        try:
            params = {
                'geocode': address,
                'apikey': app.config['YANDEX_MAPS_API_KEY'],
                'format': 'json',
                'results': 1
            }
            response = requests.get(app.config['YANDEX_GEOCODE_API'], params=params)
            response.raise_for_status()

            data = response.json()
            feature = data['response']['GeoObjectCollection']['featureMember'][0]['GeoObject']
            pos = feature['Point']['pos']
            lon, lat = map(float, pos.split())
            address = feature['metaDataProperty']['GeocoderMetaData']['text']

            return Location(latitude=lat, longitude=lon, address=address)
        except Exception as e:
            logger.error(f"Geocode failed for {address}: {str(e)}")
            return None

    @staticmethod
    @cache.memoize(timeout=86400)
    def reverse_geocode(lat: float, lon: float) -> Optional[str]:
        try:
            params = {
                'geocode': f"{lon},{lat}",
                'apikey': app.config['YANDEX_MAPS_API_KEY'],
                'format': 'json',
                'results': 1
            }
            response = requests.get(app.config['YANDEX_GEOCODE_API'], params=params)
            response.raise_for_status()

            data = response.json()
            return data['response']['GeoObjectCollection']['featureMember'][0]['GeoObject']['metaDataProperty'][
                'GeocoderMetaData']['text']
        except Exception as e:
            logger.error(f"Reverse geocode failed for {lat},{lon}: {str(e)}")
            return None

    @staticmethod
    @cache.memoize(timeout=3600)  # Кэш на 1 час
    def calculate_route(origin: Location, destination: Location, mode: str) -> Optional[Dict[str, Any]]:
        try:
            params = {
                'apikey': app.config['YANDEX_MAPS_API_KEY'],
                'waypoints': f"{origin.lon},{origin.lat}|{destination.lon},{destination.lat}",
                'mode': f"map.{mode}",
                'lang': 'ru_RU'
            }
            response = requests.get(app.config['YANDEX_ROUTER_API'], params=params)
            response.raise_for_status()

            data = response.json()
            route = data['route']['legs'][0]

            return {
                'distance': route['distance']['value'],
                'duration': route['duration']['value'],
                'steps': [
                    {
                        'instruction': step['instruction'],
                        'distance': step['distance']['value'],
                        'duration': step['duration']['value']
                    } for step in route['steps']
                ]
            }
        except Exception as e:
            logger.error(f"Route calculation failed: {str(e)}")
            return None


# --- API Namespaces ---
auth_ns = Namespace('auth', description='Аутентификация и регистрация')
maps_ns = Namespace('maps', description='Работа с Яндекс.Картами')
user_ns = Namespace('user', description='Пользовательские данные')
admin_ns = Namespace('admin', description='Администрирование')

api.add_namespace(auth_ns)
api.add_namespace(maps_ns)
api.add_namespace(user_ns)
api.add_namespace(admin_ns)

# --- Swagger модели ---
location_model = api.model('Location', {
    'latitude': fields.Float(required=True, example=55.751244),
    'longitude': fields.Float(required=True, example=37.618423),
    'address': fields.String(example='Москва, Красная площадь')
})


# --- Ресурсы API ---
@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.expect(api.model('RegisterData', {
        'username': fields.String(required=True),
        'email': fields.String(required=True),
        'password': fields.String(required=True)
    }))
    @track_request
    def post(self):
        """Регистрация нового пользователя"""
        try:
            data = request.get_json()

            if User.query.filter_by(username=data['username']).first():
                abort(400, 'Username already exists')
            if User.query.filter_by(email=data['email']).first():
                abort(400, 'Email already registered')

            user = User(
                username=data['username'],
                email=data['email'],
                role=UserRole.USER
            )
            user.set_password(data['password'])

            db.session.add(user)
            db.session.commit()

            return {'message': 'User registered successfully'}, 201
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {str(e)}")
            abort(500, 'Internal server error')


@maps_ns.route('/geocode')
class Geocode(Resource):
    @maps_ns.doc(params={'address': 'Адрес для геокодирования'})
    @jwt_required()
    @track_request
    def get(self):
        """Геокодирование адреса в координаты"""
        try:
            address = request.args.get('address')
            if not address:
                abort(400, 'Address parameter is required')

            location = YandexMapsService.geocode(address)
            if not location:
                abort(404, 'Address not found')

            return location.dict(), 200
        except Exception as e:
            logger.error(f"Geocode error: {str(e)}")
            abort(500, 'Internal server error')


@user_ns.route('/favorites')
class FavoritePlaces(Resource):
    @user_ns.doc(security='Bearer')
    @jwt_required()
    @track_request
    def get(self):
        """Получить список избранных мест"""
        try:
            user = User.query.filter_by(username=get_jwt_identity()).first()
            favorites = [
                {
                    'id': fav.id,
                    'name': fav.name,
                    'location': {
                        'latitude': fav.lat,
                        'longitude': fav.lon,
                        'address': fav.address
                    },
                    'category': fav.category,
                    'visit_count': fav.visit_count
                } for fav in user.favorites
            ]
            return favorites, 200
        except Exception as e:
            logger.error(f"Get favorites error: {str(e)}")
            abort(500, 'Internal server error')


# --- CLI команды ---
@app.cli.command('initdb')
def init_db():
    """Инициализация базы данных"""
    db.create_all()
    print("Database initialized.")


@app.cli.command('create-admin')
def create_admin():
    """Создание администратора"""
    username = input("Username: ")
    email = input("Email: ")
    password = input("Password: ")

    admin = User(
        username=username,
        email=email,
        role=UserRole.ADMIN
    )
    admin.set_password(password)

    db.session.add(admin)
    db.session.commit()
    print(f"Admin user {username} created.")


# --- Метрики Prometheus ---
if app.config['METRICS_ENABLED']:
    app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {
        '/metrics': make_wsgi_app()
    })

# --- Запуск приложения ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)