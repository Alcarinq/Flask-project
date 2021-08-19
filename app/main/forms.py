from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, Regexp, ValidationError

from ..models import User, Role


class NameForm(FlaskForm):
    name = StringField('Jak masz na imię?', validators=[DataRequired()])
    submit = SubmitField('Wyślij')


class EditProfileForm(FlaskForm):
    name = StringField('Prawdziwe imię', validators=[Length(0, 64)])
    location = StringField('Lokalizacja', validators=[Length(0, 64)])
    about_me = TextAreaField('O mnie')
    submit = SubmitField('Wyślij')


class EditProfileAdminForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Length(1, 64), Email()])

    username = StringField('Nazwa użytkownika', validators=[
        DataRequired(),
        Length(1, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Nazwy użytkownika mogą składać się tylko z liter, cyfr, kropek i _')
    ])

    confirmed = BooleanField('Potwierdzony')
    role = SelectField('Rola', coerce=int)
    name = StringField('Prawdziwe imię', validators=[Length(0, 64)])
    location = StringField('Lokalizacja', validators=[Length(0, 64)])
    about_me = TextAreaField('O mnie')
    submit = SubmitField('Wyślij')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and User.query.filter_by(email=field.data).first():
            raise ValidationError('Ten email jest już zarejestrowany.')

    def validate_username(self, field):
        if field.data != self.user.username and User.query.filter_by(username=field.data).first():
            raise ValidationError('Ta nazwa użytkownika jest już używana.')


class PostForm(FlaskForm):
    body = TextAreaField("Co chcesz dzisiaj napisać?", validators=[DataRequired()])
    submit = SubmitField('Wyślij')
