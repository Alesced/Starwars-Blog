from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import String, Boolean, Text, Date
from sqlalchemy.orm import Mapped, mapped_column
from typing import Optional
from datetime import date


db = SQLAlchemy()

# tabla de asociacion para personas favoritos
favorites_characters = db.Table(
    'favorites_characters',
    db.Column('user_id', db.Integer, db.ForeignKey(
        'user.id'), primary_key=True),
    db.Column('swapi_characters_id', db.Integer, primary_key=True)
)

# tabla de asociacion para planetas favoritos
favorites_planets = db.Table(
    'favorites_planets',
    db.Column('user_id', db.Integer, db.ForeignKey(
        'user.id'), primary_key=True),
    db.Column('swapi_planet_id', db.Integer, primary_key=True)
)

#tabla de asociacion para naves favoritas
favorites_starships = db.Table(
    'favorites_starships',
    db.Column('user_id', db.Integer, db.ForeignKey(
        'user.id'), primary_key=True),
    db.Column('swapi_starship_id', db.Integer, primary_key=True)
)


class User(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(200), nullable=False)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    first_name: Mapped[str] = mapped_column(String(50), nullable=False)
    last_name: Mapped[str] = mapped_column(String(50), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    subcription_date: Mapped[Optional[date]] = mapped_column(Date)

    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "is_active": self.is_active,
            "subcription_date": self.subcription_date.isoformat() if self.subcription_date else None,
            # do not serialize the password, its a security breach
        }