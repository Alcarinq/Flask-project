from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired
from ..models import User

class NameForm(FlaskForm):
    name = StringField('Jak masz na imię?', validators=[DataRequired()])
    submit = SubmitField('Wyślij')
